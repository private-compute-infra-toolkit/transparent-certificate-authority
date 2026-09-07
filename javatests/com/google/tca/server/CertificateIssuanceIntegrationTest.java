/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
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
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.Key;
import com.google.inject.util.Modules;
import com.google.mbs.MbsCertificateFactory;
import com.google.mbs.MeasurementBoundCertificate;
import com.google.mbs.attestationcollection.AttestationToken;
import com.google.mbs.qualifier.MbsRoot;
import com.google.oak.attestation.v1.Endorsements;
import com.google.oak.attestation.v1.Evidence;
import com.google.protobuf.ByteString;
import com.google.tca.domain.FileFetcher;
import com.google.tca.domain.TimeProvider;
import com.google.tca.domain.attestation.AttestationEvidence;
import com.google.tca.domain.attestation.AttestationVerifier;
import com.google.tca.domain.attestation.AttestationVerifierProvider;
import com.google.tca.domain.policy.ReferenceValues;
import com.google.tca.v1.IssueCertificateRequest;
import com.google.tca.v1.IssueCertificateResponse;
import com.google.tca.v1.TransparentCertificateAuthorityGrpc;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.MetadataUtils;
import io.grpc.testing.GrpcCleanupRule;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

@RunWith(Parameterized.class)
public class CertificateIssuanceIntegrationTest {
  private static final int ANY_PORT = 0;

  @Parameters(name = "{0}")
  public static Collection<Object[]> data() {
    return Arrays.asList(
        new Object[][] {{"javatests/com/google/tca/server/testdata/policy/v2/policy.textproto"}});
  }

  @Parameter public String policyPath;

  @Rule public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

  @Mock private AttestationVerifierProvider verifierProvider;
  @Mock private AttestationVerifier verifier;
  @Mock private TimeProvider timeProvider;

  private FileFetcherStub fileFetcherStub;
  private Injector injector;
  private TcaServer tcaServer;
  private ManagedChannel channel;
  private TransparentCertificateAuthorityGrpc.TransparentCertificateAuthorityBlockingStub
      blockingStub;
  private TransparentCertificateAuthorityGrpc.TransparentCertificateAuthorityBlockingStub
      baseBlockingStub;
  private PrivateKey jwtPrivateKey;

  // Helper class to return both CSR and KeyPair from the helper method.
  private static class TestCsrAndKeyPair {
    final PKCS10CertificationRequest csr;
    final KeyPair keyPair;

    TestCsrAndKeyPair(PKCS10CertificationRequest csr, KeyPair keyPair) {
      this.csr = csr;
      this.keyPair = keyPair;
    }
  }

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.initMocks(this);

    if (java.security.Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      java.security.Security.addProvider(new BouncyCastleProvider());
    }

    LocalArgs localArgs = new LocalArgs();

    // Create the MeasurementBoundCertificate instance to be used as a singleton in the test
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey =
        MbsCertificateFactory.createSelfSignedCertificatesFactory(
                new MbsCertificateFactory.CertSignatureSpec("RSA", 4096, "SHA256withRSA"),
                new X500Name("CN=TCA"),
                Duration.ofDays(30),
                Optional.of(
                    new GeneralNames(
                        new GeneralName(
                            GeneralName.uniformResourceIdentifier, "spiffe://tca.local.test"))),
                KeyUsage.keyCertSign)
            .generate();

    AttestationToken dummyToken = AttestationToken.fromBytes(new byte[0]);
    final MeasurementBoundCertificate measurementBoundCertificate =
        new MeasurementBoundCertificate(
            certAndKey.certificate(), certAndKey.privateKey(), dummyToken);

    KeyPair jwtKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    this.jwtPrivateKey = jwtKeyPair.getPrivate();
    PublicKey jwtPublicKey = jwtKeyPair.getPublic();

    fileFetcherStub =
        new FileFetcherStub(
            ByteString.copyFromUtf8(
                readTestFile(policyPath)
                    .replace("{publisher_id_to_replace}", "default_publisher_id@example.com")
                    .replace("{workload_id_to_replace}", "default_workload_id")
                    .replace(
                        "{oak_containers_reference_values}",
                        readTestFile(
                            "javatests/com/google/tca/server/testdata/reference_values.textproto"))));

    injector =
        Guice.createInjector(
            Modules.override(new TransparentCaModule())
                .with(
                    new AbstractModule() {
                      @Override
                      protected void configure() {
                        bind(AttestationVerifierProvider.class).toInstance(verifierProvider);
                        bind(FileFetcher.class).toInstance(fileFetcherStub);
                        bind(TimeProvider.class).toInstance(timeProvider);
                        // Bind the specific instances
                        bind(MeasurementBoundCertificate.class)
                            .toInstance(measurementBoundCertificate);
                        bind(X509Certificate.class)
                            .annotatedWith(MbsRoot.class)
                            .toInstance(measurementBoundCertificate.getCertificate());
                        bind(java.security.PrivateKey.class)
                            .annotatedWith(MbsRoot.class)
                            .toInstance(measurementBoundCertificate.getPrivateKey());
                        bind(new com.google.inject.TypeLiteral<
                                io.jsonwebtoken.Locator<java.security.Key>>() {})
                            .annotatedWith(JwtAuth.class)
                            .toInstance(header -> jwtPublicKey);
                        bind(AwsInstanceMetadata.class)
                            .toInstance(
                                AwsInstanceMetadata.builder()
                                    .setRegion("local")
                                    .setAccountId("dummy_account")
                                    .setEnvironment("local")
                                    .setDomain("pcit.goog")
                                    .build());
                      }
                    }));

    TransparentCertificateAuthorityGrpcHandler service =
        injector.getInstance(TransparentCertificateAuthorityGrpcHandler.class);
    TrustedCertificateAuthorityGrpcHandler legacyService =
        injector.getInstance(TrustedCertificateAuthorityGrpcHandler.class);
    JwtInterceptor jwtInterceptor = injector.getInstance(JwtInterceptor.class);
    PrometheusMeterRegistry meterRegistry = injector.getInstance(PrometheusMeterRegistry.class);

    tcaServer = new TcaServer(ANY_PORT, service, legacyService, jwtInterceptor, meterRegistry);
    tcaServer.start().join();

    channel =
        grpcCleanup.register(
            ManagedChannelBuilder.forAddress("localhost", tcaServer.port()).usePlaintext().build());

    baseBlockingStub = TransparentCertificateAuthorityGrpc.newBlockingStub(channel);

    Metadata metadata = new Metadata();
    metadata.put(
        Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER),
        "Bearer " + RequestUtils.createJwtToken(this.jwtPrivateKey));

    blockingStub =
        baseBlockingStub.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(metadata));
  }

  private TransparentCertificateAuthorityGrpc.TransparentCertificateAuthorityBlockingStub
      withTokenForCsr(PublicKey csrPublicKey) throws Exception {
    java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
    byte[] hash = md.digest(csrPublicKey.getEncoded());
    String digest = com.google.common.io.BaseEncoding.base16().lowerCase().encode(hash);
    String audience = "https://tca.local.test/v1/certificates:issue?pubkey_sha256=" + digest;

    Metadata metadata = new Metadata();
    metadata.put(
        Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER),
        "Bearer " + RequestUtils.createJwtToken(this.jwtPrivateKey, audience));

    return baseBlockingStub.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(metadata));
  }

  @After
  public void tearDown() {
    if (tcaServer != null) {
      tcaServer.stop().join();
    }
  }

  private com.google.tca.v1.AttestationEvidence createGcpEvidence(String token) {
    return com.google.tca.v1.AttestationEvidence.newBuilder()
        .setGcpAttestationEvidence(
            com.google.tca.v1.GcpAttestationEvidence.newBuilder()
                .setAttestationToken(ByteString.copyFromUtf8(token))
                .build())
        .build();
  }

  private com.google.tca.v1.AttestationEvidence createOakEvidence() {

    return com.google.tca.v1.AttestationEvidence.newBuilder()
        .setOakAttestationEvidence(
            com.google.tca.v1.OakAttestationEvidence.newBuilder()
                .setEndorsements(
                    createEndorsement(
                        RequestUtils.correctInTotoStatement(
                            "2026-03-05T10:00:00.000000Z", "3027-03-05T10:00:00.000000Z")))
                .setEvidence(Evidence.getDefaultInstance())
                .setSignedPublicKey(ByteString.copyFromUtf8(""))
                .build())
        .build();
  }

  @Test
  public void issueCertificate_missingToken_fails() {
    TransparentCertificateAuthorityGrpc.TransparentCertificateAuthorityBlockingStub nakedStub =
        TransparentCertificateAuthorityGrpc.newBlockingStub(channel);

    IssueCertificateRequest request =
        IssueCertificateRequest.newBuilder()
            .setAttestationEvidence(createGcpEvidence("token"))
            .build();

    StatusRuntimeException e =
        assertThrows(StatusRuntimeException.class, () -> nakedStub.issueCertificate(request));

    assertEquals(Status.UNAUTHENTICATED.getCode(), e.getStatus().getCode());
  }

  @Test
  public void issueCertificate_invalidJwtToken_fails() {
    Metadata metadata = new Metadata();
    metadata.put(
        Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER), "Bearer invalid-token");

    TransparentCertificateAuthorityGrpc.TransparentCertificateAuthorityBlockingStub badTokenStub =
        TransparentCertificateAuthorityGrpc.newBlockingStub(channel)
            .withInterceptors(MetadataUtils.newAttachHeadersInterceptor(metadata));

    IssueCertificateRequest request =
        IssueCertificateRequest.newBuilder()
            .setAttestationEvidence(createGcpEvidence("token"))
            .build();

    StatusRuntimeException e =
        assertThrows(StatusRuntimeException.class, () -> badTokenStub.issueCertificate(request));

    assertEquals(Status.UNAUTHENTICATED.getCode(), e.getStatus().getCode());
  }

  @Test
  public void issueCertificate_unsupportedPlatform_fails() {
    when(verifierProvider.getVerifier(any(AttestationEvidence.class))).thenReturn(Optional.empty());

    IssueCertificateRequest request =
        IssueCertificateRequest.newBuilder()
            .setAttestationEvidence(createGcpEvidence("token"))
            .build();

    StatusRuntimeException e =
        assertThrows(StatusRuntimeException.class, () -> blockingStub.issueCertificate(request));

    assertEquals(Status.INVALID_ARGUMENT.getCode(), e.getStatus().getCode());
  }

  @Test
  public void issueCertificate_invalidToken_fails() {
    when(verifierProvider.getVerifier(any(AttestationEvidence.class)))
        .thenReturn(Optional.of(verifier));
    when(verifier.verify(
            any(AttestationEvidence.class), any(PublicKey.class), any(ReferenceValues.class)))
        .thenReturn(false);

    IssueCertificateRequest request =
        IssueCertificateRequest.newBuilder()
            .setAttestationEvidence(createGcpEvidence("token"))
            .build();

    StatusRuntimeException e =
        assertThrows(StatusRuntimeException.class, () -> blockingStub.issueCertificate(request));

    assertEquals(Status.INVALID_ARGUMENT.getCode(), e.getStatus().getCode());
  }

  @Test
  public void issueCertificate_badCsr_fails() throws Exception {
    when(verifierProvider.getVerifier(any(AttestationEvidence.class)))
        .thenReturn(Optional.of(verifier));
    when(verifier.verify(
            any(AttestationEvidence.class), any(PublicKey.class), any(ReferenceValues.class)))
        .thenReturn(true);

    IssueCertificateRequest request =
        IssueCertificateRequest.newBuilder()
            .setAttestationEvidence(createGcpEvidence("token"))
            .setCertificateSigningRequest(ByteString.copyFromUtf8("bad-csr"))
            .build();

    StatusRuntimeException e =
        assertThrows(StatusRuntimeException.class, () -> blockingStub.issueCertificate(request));

    assertEquals(Status.INVALID_ARGUMENT.getCode(), e.getStatus().getCode());
  }

  @Test
  public void issueCertificate_invalidCsr_returnsInvalidArgument() throws Exception {
    when(verifierProvider.getVerifier(any(AttestationEvidence.class)))
        .thenReturn(Optional.of(verifier));
    when(verifier.verify(
            any(AttestationEvidence.class), any(PublicKey.class), any(ReferenceValues.class)))
        .thenReturn(true);

    IssueCertificateRequest request =
        IssueCertificateRequest.newBuilder()
            .setAttestationEvidence(createGcpEvidence("token"))
            .setCertificateSigningRequest(ByteString.copyFromUtf8("invalid_csr"))
            .build();

    StatusRuntimeException e =
        assertThrows(StatusRuntimeException.class, () -> blockingStub.issueCertificate(request));

    assertEquals(Status.INVALID_ARGUMENT.getCode(), e.getStatus().getCode());
    assertEquals("Invalid CSR", e.getStatus().getDescription());

    // Verify metric was incremented
    PrometheusMeterRegistry meterRegistry = injector.getInstance(PrometheusMeterRegistry.class);
    double count =
        meterRegistry.get("tca.processingStatus").tag("status", "invalid_csr").counter().count();
    assertThat(count).isEqualTo(1.0);
  }

  @Test
  public void issueCertificate_incorrectEndorsementFormat_returnsInvalidArgument()
      throws Exception {
    TestCsrAndKeyPair testCsrAndKeyPair = createTestCsr();
    IssueCertificateRequest request =
        IssueCertificateRequest.newBuilder()
            .setAttestationEvidence(
                com.google.tca.v1.AttestationEvidence.newBuilder()
                    .setOakAttestationEvidence(
                        com.google.tca.v1.OakAttestationEvidence.newBuilder()
                            .setEndorsements(Endorsements.getDefaultInstance())
                            .setEvidence(Evidence.getDefaultInstance())
                            .setSignedPublicKey(ByteString.copyFromUtf8(""))
                            .build())
                    .build())
            .setCertificateSigningRequest(ByteString.copyFrom(testCsrAndKeyPair.csr.getEncoded()))
            .build();

    TransparentCertificateAuthorityGrpc.TransparentCertificateAuthorityBlockingStub authStub =
        withTokenForCsr(testCsrAndKeyPair.keyPair.getPublic());
    StatusRuntimeException e =
        assertThrows(StatusRuntimeException.class, () -> authStub.issueCertificate(request));

    assertEquals(Status.INVALID_ARGUMENT.getCode(), e.getStatus().getCode());
    assertEquals(
        "There should be exactly 1 container endorsement, got 0", e.getStatus().getDescription());
  }

  @Test
  public void issueCertificate_validRequest_succeeds() throws Exception {
    TestCsrAndKeyPair testCsrAndKeyPair = createTestCsr();
    PKCS10CertificationRequest csr = testCsrAndKeyPair.csr;
    Instant testTime = Instant.parse("2026-03-05T12:00:00Z");

    when(timeProvider.now()).thenReturn(testTime);
    when(verifierProvider.getVerifier(any(AttestationEvidence.class)))
        .thenReturn(Optional.of(verifier));
    when(verifier.verify(
            any(AttestationEvidence.class), any(PublicKey.class), any(ReferenceValues.class)))
        .thenReturn(true);

    IssueCertificateRequest request =
        IssueCertificateRequest.newBuilder()
            .setAttestationEvidence(createOakEvidence())
            .setCertificateSigningRequest(ByteString.copyFrom(csr.getEncoded()))
            .build();

    IssueCertificateResponse response =
        withTokenForCsr(testCsrAndKeyPair.keyPair.getPublic()).issueCertificate(request);

    CertificateFactory cf = CertificateFactory.getInstance("X.509");

    assertEquals(2, response.getSignedCertificatesCount());

    X509Certificate signedCert =
        (X509Certificate)
            cf.generateCertificate(
                new ByteArrayInputStream(response.getSignedCertificates(0).toByteArray()));

    X509Certificate rootCert = injector.getInstance(Key.get(X509Certificate.class, MbsRoot.class));

    X509Certificate responseRootCert =
        (X509Certificate)
            cf.generateCertificate(
                new ByteArrayInputStream(response.getSignedCertificates(1).toByteArray()));
    assertEquals(rootCert, responseRootCert);

    signedCert.verify(rootCert.getPublicKey());
    assertEquals("CN=test", signedCert.getSubjectX500Principal().getName());

    // Verify certificate validity
    assertThat(signedCert.getNotBefore().toInstant()).isEqualTo(testTime);
    assertThat(signedCert.getNotAfter().toInstant()).isEqualTo(testTime.plusSeconds(3600));

    // Verify the SAN extension
    String expectedSpiffeId =
        "spiffe://example.org.tca.local.test/operator/example.org/test_operator_role/publisher/example.com/default_publisher_id/workload/default_workload_id";
    GeneralNames names =
        GeneralNames.getInstance(
            ASN1OctetString.getInstance(
                    signedCert.getExtensionValue(Extension.subjectAlternativeName.getId()))
                .getOctets());
    GeneralName sanEntry = names.getNames()[0];
    assertThat(sanEntry.getTagNo()).isEqualTo(GeneralName.uniformResourceIdentifier);
    assertThat(sanEntry.getName().toString()).isEqualTo(expectedSpiffeId);

    // Verify KeyUsage
    boolean[] keyUsage = signedCert.getKeyUsage();
    assertThat(keyUsage).isNotNull();
    assertThat(keyUsage[5]).isTrue(); // keyCertSign
    assertThat(keyUsage[0]).isFalse(); // digitalSignature
    assertThat(keyUsage[2]).isFalse(); // keyEncipherment

    // Verify Name Constraints
    byte[] nameConstraintsBytes = signedCert.getExtensionValue(Extension.nameConstraints.getId());
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

    assertThat(signedCert.getBasicConstraints()).isEqualTo(1);

    // Verify OIDC authentication timer metric was recorded during gRPC call
    PrometheusMeterRegistry meterRegistry = injector.getInstance(PrometheusMeterRegistry.class);
    double authTimerCount = meterRegistry.get("tca.oidc_authentication_time").timer().count();
    assertThat(authTimerCount).isGreaterThan(0.0);
  }

  @Test
  public void issueCertificate_validRequest_leafCert_succeeds() throws Exception {
    TestCsrAndKeyPair testCsrAndKeyPair = createTestCsr();
    PKCS10CertificationRequest csr = testCsrAndKeyPair.csr;
    Instant testTime = Instant.parse("2026-03-05T12:00:00Z");
    fileFetcherStub.setContent(
        ByteString.copyFromUtf8(
            readTestFile(policyPath)
                .replace("{publisher_id_to_replace}", "default_publisher_id@example.com")
                .replace("{workload_id_to_replace}", "default_workload_id")
                .replace(
                    "ca_certificate {\n            path_len_constraint: 1\n          }",
                    "leaf_certificate {}")
                .replace(
                    "{oak_containers_reference_values}",
                    readTestFile(
                        "javatests/com/google/tca/server/testdata/reference_values.textproto"))));

    when(timeProvider.now()).thenReturn(testTime);
    when(verifierProvider.getVerifier(any(AttestationEvidence.class)))
        .thenReturn(Optional.of(verifier));
    when(verifier.verify(
            any(AttestationEvidence.class), any(PublicKey.class), any(ReferenceValues.class)))
        .thenReturn(true);

    IssueCertificateRequest request =
        IssueCertificateRequest.newBuilder()
            .setAttestationEvidence(createOakEvidence())
            .setCertificateSigningRequest(ByteString.copyFrom(csr.getEncoded()))
            .build();

    IssueCertificateResponse response =
        withTokenForCsr(testCsrAndKeyPair.keyPair.getPublic()).issueCertificate(request);

    CertificateFactory cf = CertificateFactory.getInstance("X.509");

    assertEquals(2, response.getSignedCertificatesCount());

    X509Certificate signedCert =
        (X509Certificate)
            cf.generateCertificate(
                new ByteArrayInputStream(response.getSignedCertificates(0).toByteArray()));

    X509Certificate rootCert = injector.getInstance(Key.get(X509Certificate.class, MbsRoot.class));

    X509Certificate responseRootCert =
        (X509Certificate)
            cf.generateCertificate(
                new ByteArrayInputStream(response.getSignedCertificates(1).toByteArray()));
    assertEquals(rootCert, responseRootCert);

    signedCert.verify(rootCert.getPublicKey());
    assertEquals("CN=test", signedCert.getSubjectX500Principal().getName());

    // Verify certificate validity
    assertThat(signedCert.getNotBefore().toInstant()).isEqualTo(testTime);
    assertThat(signedCert.getNotAfter().toInstant()).isEqualTo(testTime.plusSeconds(3600));

    // Verify the SAN extension
    String expectedSpiffeId =
        "spiffe://example.org.tca.local.test/operator/example.org/test_operator_role/publisher/example.com/default_publisher_id/workload/default_workload_id";
    GeneralNames names =
        GeneralNames.getInstance(
            ASN1OctetString.getInstance(
                    signedCert.getExtensionValue(Extension.subjectAlternativeName.getId()))
                .getOctets());
    GeneralName sanEntry = names.getNames()[0];
    assertThat(sanEntry.getTagNo()).isEqualTo(GeneralName.uniformResourceIdentifier);
    assertThat(sanEntry.getName().toString()).isEqualTo(expectedSpiffeId);

    // Verify KeyUsage
    boolean[] keyUsage = signedCert.getKeyUsage();
    assertThat(keyUsage).isNotNull();
    assertThat(keyUsage[5]).isFalse(); // keyCertSign
    assertThat(keyUsage[0]).isTrue(); // digitalSignature
    assertThat(keyUsage[2]).isTrue(); // keyEncipherment

    assertThat(signedCert.getBasicConstraints()).isEqualTo(-1);
  }

  @Test
  public void issueCertificate_validRequestWithoutClaims_succeeds() throws Exception {
    TestCsrAndKeyPair testCsrAndKeyPair = createTestCsr();
    PKCS10CertificationRequest csr = testCsrAndKeyPair.csr;
    Instant testTime = Instant.parse("2026-03-05T12:00:00Z");

    when(timeProvider.now()).thenReturn(testTime);
    when(verifierProvider.getVerifier(any(AttestationEvidence.class)))
        .thenReturn(Optional.of(verifier));
    when(verifier.verify(
            any(AttestationEvidence.class), any(PublicKey.class), any(ReferenceValues.class)))
        .thenReturn(true);

    IssueCertificateRequest request =
        IssueCertificateRequest.newBuilder()
            .setAttestationEvidence(
                com.google.tca.v1.AttestationEvidence.newBuilder()
                    .setOakAttestationEvidence(
                        com.google.tca.v1.OakAttestationEvidence.newBuilder()
                            .setEndorsements(
                                createEndorsement(
                                    RequestUtils.correctInTotoStatementMissingClaimsPart(
                                        "2026-03-05T10:00:00.000000Z",
                                        "3027-03-05T10:00:00.000000Z")))
                            .setEvidence(Evidence.getDefaultInstance())
                            .setSignedPublicKey(ByteString.copyFromUtf8(""))
                            .build())
                    .build())
            .setCertificateSigningRequest(ByteString.copyFrom(csr.getEncoded()))
            .build();

    IssueCertificateResponse response =
        withTokenForCsr(testCsrAndKeyPair.keyPair.getPublic()).issueCertificate(request);

    assertEquals(2, response.getSignedCertificatesCount());
  }

  @Test
  public void issueCertificate_invalidRequest_missingValidity() throws Exception {
    TestCsrAndKeyPair testCsrAndKeyPair = createTestCsr();
    PKCS10CertificationRequest csr = testCsrAndKeyPair.csr;

    IssueCertificateRequest request =
        IssueCertificateRequest.newBuilder()
            .setAttestationEvidence(
                com.google.tca.v1.AttestationEvidence.newBuilder()
                    .setOakAttestationEvidence(
                        com.google.tca.v1.OakAttestationEvidence.newBuilder()
                            .setEndorsements(
                                createEndorsement(
                                    RequestUtils.incorrectInTotoStatementMissingValidityPart(
                                        "2026-03-05T10:00:00.000000Z")))
                            .setEvidence(Evidence.getDefaultInstance())
                            .setSignedPublicKey(ByteString.copyFromUtf8(""))
                            .build())
                    .build())
            .setCertificateSigningRequest(ByteString.copyFrom(csr.getEncoded()))
            .build();

    TransparentCertificateAuthorityGrpc.TransparentCertificateAuthorityBlockingStub authStub =
        withTokenForCsr(testCsrAndKeyPair.keyPair.getPublic());
    StatusRuntimeException e =
        assertThrows(StatusRuntimeException.class, () -> authStub.issueCertificate(request));

    assertThat(e.getStatus().getDescription())
        .contains("Missing required creator property 'notAfter'");
  }

  @Test
  public void issueCertificate_invalidRequest_incorrectValidityFormat() throws Exception {
    TestCsrAndKeyPair testCsrAndKeyPair = createTestCsr();
    PKCS10CertificationRequest csr = testCsrAndKeyPair.csr;

    IssueCertificateRequest request =
        IssueCertificateRequest.newBuilder()
            .setAttestationEvidence(
                com.google.tca.v1.AttestationEvidence.newBuilder()
                    .setOakAttestationEvidence(
                        com.google.tca.v1.OakAttestationEvidence.newBuilder()
                            .setEndorsements(
                                createEndorsement(
                                    RequestUtils.incorrectInTotoStatementWrongValidityFormat()))
                            .setEvidence(Evidence.getDefaultInstance())
                            .setSignedPublicKey(ByteString.copyFromUtf8(""))
                            .build())
                    .build())
            .setCertificateSigningRequest(ByteString.copyFrom(csr.getEncoded()))
            .build();

    TransparentCertificateAuthorityGrpc.TransparentCertificateAuthorityBlockingStub authStub =
        withTokenForCsr(testCsrAndKeyPair.keyPair.getPublic());
    StatusRuntimeException e =
        assertThrows(StatusRuntimeException.class, () -> authStub.issueCertificate(request));

    assertThat(e.getStatus().getDescription())
        .contains("Endorsement does not contain correct validity format");
  }

  /** Creates a KeyPair and a corresponding CSR for testing. */
  private TestCsrAndKeyPair createTestCsr() throws Exception {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048);
    KeyPair keyPair = keyPairGenerator.generateKeyPair();

    JcaPKCS10CertificationRequestBuilder p10Builder =
        new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=test"), keyPair.getPublic());
    JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
    ContentSigner signer = csBuilder.build(keyPair.getPrivate());
    PKCS10CertificationRequest csr = p10Builder.build(signer);
    return new TestCsrAndKeyPair(csr, keyPair);
  }

  private static String readTestFile(String path) throws Exception {
    return Files.readString(Paths.get(path));
  }

  @Test
  public void issueCertificate_missingEvidence_returnsInvalidArgumentAndIncrementsMetric()
      throws Exception {
    TestCsrAndKeyPair testCsrAndKeyPair = createTestCsr();
    IssueCertificateRequest request =
        IssueCertificateRequest.newBuilder()
            // Do not set attestation evidence
            .setCertificateSigningRequest(ByteString.copyFrom(testCsrAndKeyPair.csr.getEncoded()))
            .build();

    TransparentCertificateAuthorityGrpc.TransparentCertificateAuthorityBlockingStub authStub =
        withTokenForCsr(testCsrAndKeyPair.keyPair.getPublic());
    StatusRuntimeException e =
        assertThrows(StatusRuntimeException.class, () -> authStub.issueCertificate(request));

    assertEquals(Status.INVALID_ARGUMENT.getCode(), e.getStatus().getCode());
    assertEquals("Attestation evidence not set or unsupported", e.getStatus().getDescription());

    // Verify metric
    PrometheusMeterRegistry meterRegistry = injector.getInstance(PrometheusMeterRegistry.class);
    double count =
        meterRegistry
            .get("tca.processingStatus")
            .tag("status", "invalid_evidence")
            .counter()
            .count();
    assertThat(count).isEqualTo(1.0);
  }
}
