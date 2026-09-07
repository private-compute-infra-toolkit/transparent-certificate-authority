/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.tca.server;

import static com.google.common.truth.Truth.assertThat;
import static com.google.tca.server.RequestUtils.createEndorsement;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.common.io.BaseEncoding;
import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.Provides;
import com.google.inject.util.Modules;
import com.google.mbs.qualifier.MbsRoot;
import com.google.oak.attestation.v1.Evidence;
import com.google.protobuf.ByteString;
import com.google.tca.adapters.OakAttestationEvidence;
import com.google.tca.domain.CallerIdentity;
import com.google.tca.domain.CertificateIssuanceRequest;
import com.google.tca.domain.FileFetcher;
import com.google.tca.domain.TimeProvider;
import com.google.tca.domain.TransparentCaService;
import com.google.tca.domain.attestation.AttestationEvidence;
import com.google.tca.domain.attestation.AttestationVerifier;
import com.google.tca.domain.policy.ReferenceValues;
import jakarta.inject.Singleton;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public class CertificateIssuanceComponentTest {

  @Parameters(name = "{0}")
  public static Collection<Object[]> data() {
    return Arrays.asList(
        new Object[][] {{"javatests/com/google/tca/server/testdata/policy/v2/policy.textproto"}});
  }

  @Parameter public String policyPath;

  private TransparentCaService transparentCaService;
  private X509Certificate rootCertificate;
  private AttestationVerifier mockVerifier;
  private TimeProvider mockTimeProvider;

  @Before
  public void setUp() throws Exception {
    Path configPath = Files.createTempFile("test_tca_config", ".json");
    try (InputStream in =
        CertificateIssuanceComponentTest.class.getResourceAsStream(
            "/com/google/tca/server/testdata/test_tca_config.json")) {
      Files.copy(in, configPath, StandardCopyOption.REPLACE_EXISTING);
    }

    LocalArgs localArgs = new LocalArgs();
    java.lang.reflect.Field field = LocalArgs.class.getDeclaredField("configPath");
    field.setAccessible(true);
    field.set(localArgs, configPath.toString());

    mockVerifier = mock(AttestationVerifier.class);
    mockTimeProvider = mock(TimeProvider.class);

    FileFetcher fileFetcher =
        new FileFetcherStub(
            ByteString.copyFromUtf8(
                readTestFile(policyPath)
                    .replace("{publisher_id_to_replace}", "default_publisher_id@example.com")
                    .replace("{workload_id_to_replace}", "default_workload_id")
                    .replace("issuer: \"https://accounts.google.com\"", "issuer: \"test-issuer\"")
                    .replace("subject: \"jwt-token-test-sub\"", "subject: \"test-subject\"")
                    .replace(
                        "{oak_containers_reference_values}",
                        readTestFile(
                            "javatests/com/google/tca/server/testdata/reference_values.textproto"))));

    Injector injector =
        Guice.createInjector(
            Modules.override(new TransparentCaModule())
                .with(
                    new AbstractModule() {
                      @Override
                      protected void configure() {
                        bind(FileFetcher.class).toInstance(fileFetcher);
                        bind(TimeProvider.class).toInstance(mockTimeProvider);
                      }

                      @Provides
                      @Singleton
                      Map<Class<? extends AttestationEvidence>, AttestationVerifier>
                          provideVerifiers() {
                        return Collections.singletonMap(OakAttestationEvidence.class, mockVerifier);
                      }
                    }),
            new LocalModeModule(localArgs));

    transparentCaService = injector.getInstance(TransparentCaService.class);
    rootCertificate = injector.getInstance(Key.get(X509Certificate.class, MbsRoot.class));
  }

  @Test
  public void issueCertificate_validRequest_succeeds() throws Exception {
    KeyPair keyPair = generateKeyPair();
    PKCS10CertificationRequest csr = createTestCsr(keyPair);
    Instant testTime = Instant.parse("2026-03-05T12:00:00Z");
    Instant notBefore = testTime.plusSeconds(100);
    Instant notAfter = testTime.plusSeconds(800);

    when(mockTimeProvider.now()).thenReturn(testTime);

    when(mockVerifier.verify(
            any(AttestationEvidence.class), any(PublicKey.class), any(ReferenceValues.class)))
        .thenReturn(true);

    CertificateIssuanceRequest request =
        CertificateIssuanceRequest.builder()
            .setAttestationEvidence(
                OakAttestationEvidence.create(
                    Evidence.getDefaultInstance(),
                    createEndorsement(
                        RequestUtils.correctInTotoStatement(
                            notBefore.toString(), notAfter.toString())),
                    ByteString.copyFromUtf8("signedPublicKey1")))
            .setCertificateSigningRequest(ByteString.copyFrom(csr.getEncoded()))
            .build();

    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] hash = md.digest(keyPair.getPublic().getEncoded());
    String digest = BaseEncoding.base16().lowerCase().encode(hash);
    String expectedAudience =
        "https://tca.local.test/v1/certificates:issue?pubkey_sha256=" + digest;

    List<X509Certificate> issuedCerts =
        transparentCaService.issueCertificate(
            request,
            new CallerIdentity("test-issuer", "test-subject", java.util.Set.of(expectedAudience)));

    assertEquals(2, issuedCerts.size());

    X509Certificate issuedCert = issuedCerts.get(0);
    assertEquals("CN=test", issuedCert.getSubjectX500Principal().getName());
    issuedCert.verify(rootCertificate.getPublicKey());

    // Verify certificate validity
    assertThat(issuedCert.getNotBefore().toInstant()).isEqualTo(notBefore);
    assertThat(issuedCert.getNotAfter().toInstant()).isEqualTo(notAfter);

    // Verify the SAN extension
    String expectedSpiffeId =
        "spiffe://example.org.tca.local.test/operator/example.org/test_operator_role/publisher/example.com/default_publisher_id/workload/default_workload_id";
    GeneralNames names =
        GeneralNames.getInstance(
            ASN1OctetString.getInstance(
                    issuedCert.getExtensionValue(Extension.subjectAlternativeName.getId()))
                .getOctets());
    GeneralName sanEntry = names.getNames()[0];
    assertThat(sanEntry.getTagNo()).isEqualTo(GeneralName.uniformResourceIdentifier);
    assertThat(sanEntry.getName().toString()).isEqualTo(expectedSpiffeId);

    // Verify Name Constraints
    byte[] nameConstraintsBytes = issuedCert.getExtensionValue(Extension.nameConstraints.getId());
    assertThat(nameConstraintsBytes).isNotNull();
    try (ASN1InputStream is =
        new ASN1InputStream(new java.io.ByteArrayInputStream(nameConstraintsBytes))) {
      ASN1OctetString octetString = (ASN1OctetString) is.readObject();
      NameConstraints nameConstraints = NameConstraints.getInstance(octetString.getOctets());

      GeneralSubtree[] permitted = nameConstraints.getPermittedSubtrees();
      assertThat(permitted).hasLength(2);
      assertThat(permitted[0].getBase().getTagNo())
          .isEqualTo(GeneralName.uniformResourceIdentifier);
      assertThat(permitted[0].getBase().getName().toString())
          .isEqualTo(".example1.org.tca.local.test");
      assertThat(permitted[1].getBase().getTagNo())
          .isEqualTo(GeneralName.uniformResourceIdentifier);
      assertThat(permitted[1].getBase().getName().toString())
          .isEqualTo(".example2.org.tca.local.test");
    }

    assertEquals(rootCertificate, issuedCerts.get(1));
  }

  private static KeyPair generateKeyPair() throws NoSuchAlgorithmException {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    return keyPairGenerator.generateKeyPair();
  }

  private PKCS10CertificationRequest createTestCsr(KeyPair keyPair) throws Exception {
    JcaPKCS10CertificationRequestBuilder p10Builder =
        new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=test"), keyPair.getPublic());
    JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
    ContentSigner signer = csBuilder.build(keyPair.getPrivate());
    return p10Builder.build(signer);
  }

  private static String readTestFile(String path) throws Exception {
    return Files.readString(Paths.get(path));
  }
}
