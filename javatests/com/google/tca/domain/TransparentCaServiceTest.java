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

package com.google.tca.domain;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.AdditionalMatchers.aryEq;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.common.io.BaseEncoding;
import com.google.protobuf.ByteString;
import com.google.tca.domain.attestation.AttestationEvidence;
import com.google.tca.domain.attestation.AttestationVerifier;
import com.google.tca.domain.attestation.AttestationVerifierProvider;
import com.google.tca.domain.attestation.EndorsementAnnotations;
import com.google.tca.domain.attestation.Validity;
import com.google.tca.domain.metric.IssuanceSubOperation;
import com.google.tca.domain.metric.Metrics;
import com.google.tca.domain.metric.ProcessingStatus;
import com.google.tca.domain.policy.Policy;
import com.google.tca.domain.policy.ReferenceValues;
import com.google.tca.domain.policy.ReferenceValuesType;
import com.google.tca.domain.policy.X500NameAttributes;
import com.google.tca.domain.policy.X509CertificateAttributes;
import com.google.tca.domain.policy.X509Extensions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

@RunWith(JUnit4.class)
public class TransparentCaServiceTest {

  @Mock private X509Certificate mockRootCertificate;
  @Mock private X509Certificate mockChildCertificate;
  @Mock private PrivateKey mockPrivateKey;
  @Mock private AttestationVerifierProvider mockVerifierProvider;
  @Mock private AttestationVerifier mockAttestationVerifier;
  @Mock private CertificateSigner mockCertificateSigner;
  @Mock private KeyDecoder mockKeyDecoder;
  @Mock private AttestationEvidence mockkAttestationEvidence;
  @Mock private PolicyProvider mockPolicyProvider;
  @Mock private TimeProvider mockTimeProvider;
  @Mock private EndorsementMetadataProvider mockEndorsementMetadataProvider;
  @Mock private CertificateModifiersCreator mockCertificateModifiersCreator;
  @Mock private AudienceBindingValidator mockAudienceBindingValidator;
  @Mock private Metrics mockMetrics;

  final Instant testTime = Instant.parse("2026-06-17T16:14:30.513000Z");

  private TransparentCaService transparentCaService;

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.initMocks(this);
    when(mockMetrics.startIssuanceTimer())
        .thenAnswer(
            invocation ->
                new Metrics.IssuanceTimer() {
                  private long subOpStartNano = System.nanoTime();

                  @Override
                  public void recordSubOperationAndResetTimer(IssuanceSubOperation operation) {
                    long now = System.nanoTime();
                    mockMetrics.recordIssuanceSubOperationTime(
                        operation, java.time.Duration.ofNanos(now - subOpStartNano));
                    subOpStartNano = now;
                  }
                });
    transparentCaService =
        new TransparentCaService(
            mockRootCertificate,
            mockPrivateKey,
            mockVerifierProvider,
            mockCertificateSigner,
            mockKeyDecoder,
            mockPolicyProvider,
            mockTimeProvider,
            mockEndorsementMetadataProvider,
            mockCertificateModifiersCreator,
            mockAudienceBindingValidator,
            mockMetrics);
  }

  @Test
  public void issueCertificate_validRequest_succeeds() throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    PKCS10CertificationRequest csr = createTestCsr(keyPair);
    byte[] csrBytes = csr.getEncoded();

    CertificateIssuanceRequest request = createValidRequest(csrBytes);

    when(mockVerifierProvider.getVerifier(any(AttestationEvidence.class)))
        .thenReturn(Optional.of(mockAttestationVerifier));
    when(mockAttestationVerifier.verify(
            any(AttestationEvidence.class), any(PublicKey.class), any(ReferenceValues.class)))
        .thenReturn(true);
    when(mockKeyDecoder.decodeRawPublicKey(any())).thenReturn(keyPair.getPublic());
    when(mockPolicyProvider.getPolicy(any(), any(), any()))
        .thenReturn(Optional.of(createValidPolicy()));
    when(mockEndorsementMetadataProvider.getAnnotations(any()))
        .thenReturn(createValidEndorsementProperties());
    when(mockEndorsementMetadataProvider.getValidity(any())).thenReturn(createValidity());
    when(mockkAttestationEvidence.getReferenceValuesType()).thenReturn(ReferenceValuesType.GCP);
    when(mockTimeProvider.now()).thenReturn(testTime);
    when(mockCertificateModifiersCreator.create(any())).thenReturn(List.of());

    TransparentCaService serviceWithRealCrypto =
        new TransparentCaService(
            mockRootCertificate,
            mockPrivateKey,
            mockVerifierProvider,
            mockCertificateSigner,
            mockKeyDecoder,
            mockPolicyProvider,
            mockTimeProvider,
            mockEndorsementMetadataProvider,
            mockCertificateModifiersCreator,
            mockAudienceBindingValidator,
            mockMetrics);

    when(mockCertificateSigner.signCsr(
            aryEq(csrBytes),
            eq(mockRootCertificate),
            eq(mockPrivateKey),
            any(),
            any(),
            any(),
            eq(new X500Principal("CN=policy-subject"))))
        .thenReturn(mockChildCertificate);

    List<X509Certificate> signedCerts =
        serviceWithRealCrypto.issueCertificate(
            request, createIdentityWithBinding(keyPair.getPublic()));
    assertEquals(2, signedCerts.size());
    assertEquals(signedCerts.get(0), mockChildCertificate);
    assertEquals(signedCerts.get(1), mockRootCertificate);
    verify(mockMetrics).incrementCertificateIssuanceCounter("issuer/subject");
    verify(mockMetrics)
        .recordIssuanceSubOperationTime(eq(IssuanceSubOperation.EXTRACT_PUBLIC_KEY), any());
    verify(mockMetrics)
        .recordIssuanceSubOperationTime(eq(IssuanceSubOperation.VALIDATE_AUDIENCE), any());
    verify(mockMetrics)
        .recordIssuanceSubOperationTime(
            eq(IssuanceSubOperation.ENDORSEMENT_METADATA_PARSING), any());
    verify(mockMetrics)
        .recordIssuanceSubOperationTime(eq(IssuanceSubOperation.POLICY_RESOLUTION), any());
    verify(mockMetrics)
        .recordIssuanceSubOperationTime(eq(IssuanceSubOperation.VERIFIER_RESOLUTION), any());
    verify(mockMetrics)
        .recordIssuanceSubOperationTime(eq(IssuanceSubOperation.VERIFY_ATTESTATION), any());
    verify(mockMetrics)
        .recordIssuanceSubOperationTime(eq(IssuanceSubOperation.SIGN_CERTIFICATE), any());
  }

  @Test
  public void issueCertificate_mismatchedAudienceBinding_succeedsButLogsError() throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    KeyPair differentKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    PKCS10CertificationRequest csr = createTestCsr(keyPair);
    byte[] csrBytes = csr.getEncoded();

    CertificateIssuanceRequest request = createValidRequest(csrBytes);

    when(mockVerifierProvider.getVerifier(any(AttestationEvidence.class)))
        .thenReturn(Optional.of(mockAttestationVerifier));
    when(mockAttestationVerifier.verify(
            any(AttestationEvidence.class), any(PublicKey.class), any(ReferenceValues.class)))
        .thenReturn(true);
    when(mockKeyDecoder.decodeRawPublicKey(any())).thenReturn(keyPair.getPublic());
    when(mockPolicyProvider.getPolicy(any(), any(), any()))
        .thenReturn(Optional.of(createValidPolicy()));
    when(mockEndorsementMetadataProvider.getAnnotations(any()))
        .thenReturn(createValidEndorsementProperties());
    when(mockEndorsementMetadataProvider.getValidity(any())).thenReturn(createValidity());
    when(mockkAttestationEvidence.getReferenceValuesType()).thenReturn(ReferenceValuesType.GCP);
    when(mockTimeProvider.now()).thenReturn(testTime);
    when(mockCertificateModifiersCreator.create(any())).thenReturn(List.of());

    when(mockCertificateSigner.signCsr(
            aryEq(csrBytes),
            eq(mockRootCertificate),
            eq(mockPrivateKey),
            any(),
            any(),
            any(),
            eq(new X500Principal("CN=policy-subject"))))
        .thenReturn(mockChildCertificate);

    // Identity has binding for a different key
    CallerIdentity identity = createIdentityWithBinding(differentKeyPair.getPublic());

    List<X509Certificate> signedCerts = transparentCaService.issueCertificate(request, identity);
    assertEquals(2, signedCerts.size());
    assertEquals(signedCerts.get(0), mockChildCertificate);
    assertEquals(signedCerts.get(1), mockRootCertificate);
  }

  @Test
  public void issueCertificate_missingAudienceBinding_succeedsButLogsError() throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    PKCS10CertificationRequest csr = createTestCsr(keyPair);
    byte[] csrBytes = csr.getEncoded();

    CertificateIssuanceRequest request = createValidRequest(csrBytes);

    when(mockVerifierProvider.getVerifier(any(AttestationEvidence.class)))
        .thenReturn(Optional.of(mockAttestationVerifier));
    when(mockAttestationVerifier.verify(
            any(AttestationEvidence.class), any(PublicKey.class), any(ReferenceValues.class)))
        .thenReturn(true);
    when(mockKeyDecoder.decodeRawPublicKey(any())).thenReturn(keyPair.getPublic());
    when(mockPolicyProvider.getPolicy(any(), any(), any()))
        .thenReturn(Optional.of(createValidPolicy()));
    when(mockEndorsementMetadataProvider.getAnnotations(any()))
        .thenReturn(createValidEndorsementProperties());
    when(mockEndorsementMetadataProvider.getValidity(any())).thenReturn(createValidity());
    when(mockkAttestationEvidence.getReferenceValuesType()).thenReturn(ReferenceValuesType.GCP);
    when(mockTimeProvider.now()).thenReturn(testTime);
    when(mockCertificateModifiersCreator.create(any())).thenReturn(List.of());

    when(mockCertificateSigner.signCsr(
            aryEq(csrBytes),
            eq(mockRootCertificate),
            eq(mockPrivateKey),
            any(),
            any(),
            any(),
            eq(new X500Principal("CN=policy-subject"))))
        .thenReturn(mockChildCertificate);

    List<X509Certificate> signedCerts =
        transparentCaService.issueCertificate(
            request, new CallerIdentity("issuer", "subject", Set.of()));
    assertEquals(2, signedCerts.size());
    assertEquals(signedCerts.get(0), mockChildCertificate);
    assertEquals(signedCerts.get(1), mockRootCertificate);
  }

  @Test
  public void issueCertificate_unsupportedPlatform_throwsIllegalArgumentException()
      throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    PKCS10CertificationRequest csr = createTestCsr(keyPair);
    CertificateIssuanceRequest request = createValidRequest(csr.getEncoded());
    when(mockKeyDecoder.decodeRawPublicKey(any())).thenReturn(keyPair.getPublic());
    when(mockPolicyProvider.getPolicy(any(), any(), any()))
        .thenReturn(Optional.of(createValidPolicy()));
    when(mockEndorsementMetadataProvider.getAnnotations(any()))
        .thenReturn(createValidEndorsementProperties());

    when(mockVerifierProvider.getVerifier(any(AttestationEvidence.class)))
        .thenReturn(Optional.empty());
    when(mockkAttestationEvidence.getReferenceValuesType()).thenReturn(ReferenceValuesType.GCP);

    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                transparentCaService.issueCertificate(
                    request, new CallerIdentity("test-issuer", "test-subject", Set.of())));
    assertEquals("Unsupported attestation platform", e.getMessage());
    verify(mockMetrics, never()).incrementCertificateIssuanceCounter(any());
  }

  @Test
  public void issueCertificate_invalidToken_throwsIllegalArgumentException() throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    PKCS10CertificationRequest csr = createTestCsr(keyPair);
    CertificateIssuanceRequest request = createValidRequest(csr.getEncoded());
    when(mockKeyDecoder.decodeRawPublicKey(any())).thenReturn(keyPair.getPublic());

    when(mockVerifierProvider.getVerifier(any(AttestationEvidence.class)))
        .thenReturn(Optional.of(mockAttestationVerifier));
    when(mockAttestationVerifier.verify(
            any(AttestationEvidence.class), any(PublicKey.class), any(ReferenceValues.class)))
        .thenReturn(false);
    when(mockPolicyProvider.getPolicy(any(), any(), any()))
        .thenReturn(Optional.of(createValidPolicy()));
    when(mockEndorsementMetadataProvider.getAnnotations(any()))
        .thenReturn(createValidEndorsementProperties());
    when(mockkAttestationEvidence.getReferenceValuesType()).thenReturn(ReferenceValuesType.GCP);

    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                transparentCaService.issueCertificate(
                    request, new CallerIdentity("test-issuer", "test-subject", Set.of())));
    assertEquals("Attestation token is not valid", e.getMessage());
    verify(mockMetrics, never()).incrementCertificateIssuanceCounter(any());
  }

  @Test
  public void issueCertificate_wrongKey_throwsIllegalArgumentException() throws Exception {
    KeyPair csrKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    KeyPair differentKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();

    PKCS10CertificationRequest csr = createTestCsr(csrKeyPair);
    byte[] csrBytes = csr.getEncoded();
    CertificateIssuanceRequest request = createValidRequest(csrBytes);

    when(mockVerifierProvider.getVerifier(any(AttestationEvidence.class)))
        .thenReturn(Optional.of(mockAttestationVerifier));
    // Verifier returns false when keys don't match
    when(mockAttestationVerifier.verify(
            any(AttestationEvidence.class), any(PublicKey.class), any(ReferenceValues.class)))
        .thenReturn(false);
    when(mockKeyDecoder.decodeRawPublicKey(any())).thenReturn(csrKeyPair.getPublic());
    when(mockPolicyProvider.getPolicy(any(), any(), any()))
        .thenReturn(Optional.of(createValidPolicy()));
    when(mockEndorsementMetadataProvider.getAnnotations(any()))
        .thenReturn(createValidEndorsementProperties());
    when(mockkAttestationEvidence.getReferenceValuesType()).thenReturn(ReferenceValuesType.GCP);

    IllegalArgumentException e =
        assertThrows(
            IllegalArgumentException.class,
            () ->
                transparentCaService.issueCertificate(
                    request, new CallerIdentity("test-issuer", "test-subject", Set.of())));
    assertEquals("Attestation token is not valid", e.getMessage());
  }

  private CallerIdentity createIdentityWithBinding(PublicKey publicKey) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] hash = md.digest(publicKey.getEncoded());
    String digest = BaseEncoding.base16().lowerCase().encode(hash);
    String audience = "https://tca.pcit.goog/v1/certificates:issue?pubkey_sha256=" + digest;
    return new CallerIdentity("issuer", "subject", Set.of(audience));
  }

  private CertificateIssuanceRequest createValidRequest(byte[] csrBytes) {
    return CertificateIssuanceRequest.builder()
        .setAttestationEvidence(createEvidence())
        .setCertificateSigningRequest(ByteString.copyFrom(csrBytes))
        .build();
  }

  private CertificateIssuanceRequest createStubRequest() {
    return CertificateIssuanceRequest.builder()
        .setAttestationEvidence(createEvidence())
        .setCertificateSigningRequest(ByteString.copyFromUtf8("foo"))
        .build();
  }

  private AttestationEvidence createEvidence() {
    return mockkAttestationEvidence;
  }

  private PKCS10CertificationRequest createTestCsr(KeyPair keyPair) throws Exception {
    JcaPKCS10CertificationRequestBuilder p10Builder =
        new JcaPKCS10CertificationRequestBuilder(new X500Name("CN=test"), keyPair.getPublic());
    JcaContentSignerBuilder csBuilder = new JcaContentSignerBuilder("SHA256withRSA");
    ContentSigner signer = csBuilder.build(keyPair.getPrivate());
    return p10Builder.build(signer);
  }

  private Policy createValidPolicy() {
    return Policy.builder()
        .setPublisherId("test-publisher")
        .setWorkloadId("test-app")
        .setOperatorDomain("example.com")
        .setOperatorRole("test-operator-role")
        .setReferenceValuesList(
            List.of(new ReferenceValues(ReferenceValuesType.GCP, ByteString.EMPTY)))
        .setCertificateAttributes(
            new X509CertificateAttributes(
                Duration.ofHours(1),
                new X509Extensions(Optional.empty(), Optional.empty()),
                new X500NameAttributes(Map.of("2.5.4.3", "policy-subject"))))
        .build();
  }

  private EndorsementAnnotations createValidEndorsementProperties() {
    return new EndorsementAnnotations("pub1", "wl1");
  }

  private Validity createValidity() {
    return new Validity(testTime.minusSeconds(100), testTime.plusSeconds(1000));
  }

  @Test
  public void issueCertificate_invalidCsr_throwsIOExceptionAndIncrementsMetric() throws Exception {
    CertificateIssuanceRequest request = createStubRequest(); // "foo" is invalid CSR

    assertThrows(
        java.io.IOException.class,
        () ->
            transparentCaService.issueCertificate(
                request, new CallerIdentity("issuer", "subject", Set.of())));

    verify(mockMetrics).incrementProcessingCounter(ProcessingStatus.INVALID_CSR);
  }

  @Test
  public void
      issueCertificate_audienceMismatch_throwsAudienceValidationExceptionAndIncrementsMetric()
          throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    PKCS10CertificationRequest csr = createTestCsr(keyPair);
    CertificateIssuanceRequest request = createValidRequest(csr.getEncoded());

    when(mockKeyDecoder.decodeRawPublicKey(any())).thenReturn(keyPair.getPublic());
    doThrow(new AudienceValidationException("audience mismatch"))
        .when(mockAudienceBindingValidator)
        .validate(any(), any());

    assertThrows(
        AudienceValidationException.class,
        () ->
            transparentCaService.issueCertificate(
                request, new CallerIdentity("issuer", "subject", Set.of())));

    verify(mockMetrics).incrementProcessingCounter(ProcessingStatus.AUDIENCE_MISMATCH);
  }

  @Test
  public void issueCertificate_signingError_throwsCertificateExceptionAndIncrementsMetric()
      throws Exception {
    KeyPair keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    PKCS10CertificationRequest csr = createTestCsr(keyPair);
    CertificateIssuanceRequest request = createValidRequest(csr.getEncoded());

    when(mockVerifierProvider.getVerifier(any(AttestationEvidence.class)))
        .thenReturn(Optional.of(mockAttestationVerifier));
    when(mockAttestationVerifier.verify(
            any(AttestationEvidence.class), any(PublicKey.class), any(ReferenceValues.class)))
        .thenReturn(true);
    when(mockKeyDecoder.decodeRawPublicKey(any())).thenReturn(keyPair.getPublic());
    when(mockPolicyProvider.getPolicy(any(), any(), any()))
        .thenReturn(Optional.of(createValidPolicy()));
    when(mockEndorsementMetadataProvider.getAnnotations(any()))
        .thenReturn(createValidEndorsementProperties());
    when(mockEndorsementMetadataProvider.getValidity(any())).thenReturn(createValidity());
    when(mockkAttestationEvidence.getReferenceValuesType()).thenReturn(ReferenceValuesType.GCP);
    when(mockTimeProvider.now()).thenReturn(testTime);
    when(mockCertificateModifiersCreator.create(any())).thenReturn(List.of());

    when(mockCertificateSigner.signCsr(any(), any(), any(), any(), any(), any(), any()))
        .thenThrow(new java.security.cert.CertificateException("signing failed"));

    assertThrows(
        java.security.cert.CertificateException.class,
        () ->
            transparentCaService.issueCertificate(
                request, createIdentityWithBinding(keyPair.getPublic())));

    verify(mockMetrics).incrementProcessingCounter(ProcessingStatus.SIGNING_ERROR);
  }
}
