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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThrows;
import static org.mockito.Mockito.when;

import com.google.inject.AbstractModule;
import com.google.inject.Guice;
import com.google.inject.Injector;
import com.google.inject.util.Modules;
import com.google.mbs.MbsCertificateFactory;
import com.google.mbs.MeasurementBoundCertificate;
import com.google.mbs.attestationcollection.AttestationToken;
import com.google.tca.adapters.PolicyBucket;
import com.google.tca.domain.TimeProvider;
import com.google.tca.domain.metric.Metrics;
import com.google.tca.domain.metric.ProcessingStatus;
import com.google.tca.v1.IssueCertificateRequest;
import com.google.tca.v1.IssueCertificateResponse;
import com.google.tca.v1.TransparentCertificateAuthorityGrpc;
import com.linecorp.armeria.client.WebClient;
import com.linecorp.armeria.common.AggregatedHttpResponse;
import com.linecorp.armeria.common.HttpStatus;
import io.grpc.ManagedChannel;
import io.grpc.ManagedChannelBuilder;
import io.grpc.Metadata;
import io.grpc.Status;
import io.grpc.StatusRuntimeException;
import io.grpc.stub.MetadataUtils;
import io.grpc.testing.GrpcCleanupRule;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.NameConstraints;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.testcontainers.containers.localstack.LocalStackContainer;
import org.testcontainers.utility.DockerImageName;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.DeleteObjectRequest;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Request;
import software.amazon.awssdk.services.s3.model.ListObjectsV2Response;
import software.amazon.awssdk.services.s3.model.PutObjectRequest;
import software.amazon.awssdk.services.s3.model.S3Object;

@RunWith(Parameterized.class)
public class FullIntegrationTest {

  @Parameters(name = "{0}")
  public static java.util.Collection<Object[]> data() {
    return java.util.Arrays.asList(
        new Object[][] {
          {"javatests/com/google/tca/server/testdata/policy/v1/policy.textproto"},
          {"javatests/com/google/tca/server/testdata/policy/v2/policy.textproto"}
        });
  }

  @Parameter public String policyPath;
  private static final int ANY_PORT = 0;

  @Rule public final GrpcCleanupRule grpcCleanup = new GrpcCleanupRule();

  @Mock private TimeProvider timeProvider;

  private static S3Client s3Client;
  private static final String BUCKET_NAME = "test-bucket";

  private Injector injector;
  private TcaServer tcaServer;
  private WebClient httpClient;
  private TransparentCertificateAuthorityGrpc.TransparentCertificateAuthorityBlockingStub client;
  private TransparentCertificateAuthorityGrpc.TransparentCertificateAuthorityBlockingStub
      baseBlockingStub;
  private java.security.PrivateKey jwtPrivateKey;

  public static LocalStackContainer localstack =
      new LocalStackContainer(DockerImageName.parse("localstack/localstack:4.14.0"))
          .withServices(LocalStackContainer.Service.S3)
          .withStartupTimeout(Duration.ofSeconds(120));

  @BeforeClass
  public static void setUpClass() {
    localstack.start();
    initializeS3Client();
  }

  @AfterClass
  public static void cleanUpClass() {
    localstack.stop();
  }

  @Before
  public void setUp() throws Exception {
    MockitoAnnotations.initMocks(this);
    createS3TestBucket();
    setupServerAndClient();
  }

  @After
  public void tearDown() {
    if (tcaServer != null) {
      tcaServer.stop().join();
    }
  }

  private void setupServerAndClient() throws CertificateException, IOException {
    LocalArgs localArgs = new LocalArgs();

    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }

    // Create the MeasurementBoundCertificate instance to be used as a singleton in the test
    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey =
        MbsCertificateFactory.createSelfSignedCertificatesFactory(
                new MbsCertificateFactory.CertSignatureSpec("RSA", 4096, "SHA256withRSA"),
                new X500Name("CN=Standalone CA"),
                Duration.ofDays(30),
                Optional.of(
                    new GeneralNames(
                        new GeneralName(
                            GeneralName.uniformResourceIdentifier, "spiffe://tca.local.test"))),
                KeyUsage.keyCertSign)
            .generate();

    AttestationToken dummyToken = AttestationToken.fromBytes(new byte[0]);
    final MeasurementBoundCertificate mbs =
        new MeasurementBoundCertificate(
            certAndKey.certificate(), certAndKey.privateKey(), dummyToken);

    java.security.KeyPair jwtKeyPair;
    try {
      java.security.KeyPairGenerator keyPairGenerator =
          java.security.KeyPairGenerator.getInstance("RSA");
      keyPairGenerator.initialize(2048);
      jwtKeyPair = keyPairGenerator.generateKeyPair();
    } catch (java.security.NoSuchAlgorithmException e) {
      throw new RuntimeException(e);
    }
    this.jwtPrivateKey = jwtKeyPair.getPrivate();
    java.security.PublicKey jwtPublicKey = jwtKeyPair.getPublic();

    injector =
        Guice.createInjector(
            Modules.override(new TransparentCaModule())
                .with(
                    new AbstractModule() {
                      @Override
                      protected void configure() {
                        bind(TimeProvider.class).toInstance(timeProvider);
                        bind(S3Client.class).toInstance(s3Client);
                        bind(String.class)
                            .annotatedWith(PolicyBucket.class)
                            .toInstance(BUCKET_NAME);
                        bind(MeasurementBoundCertificate.class).toInstance(mbs);
                        bind(X509Certificate.class).toInstance(mbs.getCertificate());
                        bind(java.security.PrivateKey.class).toInstance(mbs.getPrivateKey());
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

    httpClient = WebClient.of("http://127.0.0.1:" + tcaServer.port());

    ManagedChannel channel =
        grpcCleanup.register(
            ManagedChannelBuilder.forAddress("localhost", tcaServer.port()).usePlaintext().build());

    baseBlockingStub = TransparentCertificateAuthorityGrpc.newBlockingStub(channel);

    Metadata metadata = new Metadata();
    metadata.put(
        Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER),
        "Bearer " + RequestUtils.createJwtToken(this.jwtPrivateKey));

    client = baseBlockingStub.withInterceptors(MetadataUtils.newAttachHeadersInterceptor(metadata));
  }

  private TransparentCertificateAuthorityGrpc.TransparentCertificateAuthorityBlockingStub
      withTokenForCsr(byte[] csrBytes) throws Exception {
    org.bouncycastle.pkcs.PKCS10CertificationRequest csr =
        new org.bouncycastle.pkcs.PKCS10CertificationRequest(csrBytes);
    byte[] csrPublicKeyBytes = csr.getSubjectPublicKeyInfo().getEncoded();
    java.security.PublicKey csrPublicKey =
        injector
            .getInstance(com.google.tca.domain.KeyDecoder.class)
            .decodeRawPublicKey(csrPublicKeyBytes);

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

  private static void initializeS3Client() {
    s3Client =
        S3Client.builder()
            .endpointOverride(localstack.getEndpointOverride(LocalStackContainer.Service.S3))
            .credentialsProvider(
                StaticCredentialsProvider.create(
                    AwsBasicCredentials.create(
                        localstack.getAccessKey(), localstack.getSecretKey())))
            .forcePathStyle(true)
            .region(Region.of(localstack.getRegion()))
            .build();
  }

  private void createS3TestBucket() {
    ListObjectsV2Request listReq = ListObjectsV2Request.builder().bucket(BUCKET_NAME).build();
    try {
      ListObjectsV2Response listRes = s3Client.listObjectsV2(listReq);
      for (S3Object s3Object : listRes.contents()) {
        s3Client.deleteObject(
            DeleteObjectRequest.builder().bucket(BUCKET_NAME).key(s3Object.key()).build());
      }
    } catch (Exception e) {
      // Bucket does not exist on the first run
    }

    try {
      s3Client.createBucket(b -> b.bucket(BUCKET_NAME));
    } catch (Exception e) {
      // Bucket exists on following runs
    }
  }

  @Test
  public void issueCertificate_validRequest_succeeds() throws Exception {

    GoldenRequest goldenRequest = new GoldenRequest();

    uploadPolicyToS3(goldenRequest.getPublisherId(), goldenRequest.getWorkloadId());
    Instant testTime =
        goldenRequest.getNotBefore().plusSeconds(10000).truncatedTo(ChronoUnit.SECONDS);
    IssueCertificateRequest request = goldenRequest.getRequestBody();

    when(timeProvider.currentTimeMillis()).thenReturn(testTime.toEpochMilli());
    when(timeProvider.now()).thenReturn(Instant.ofEpochMilli(testTime.toEpochMilli()));

    IssueCertificateResponse response =
        withTokenForCsr(request.getCertificateSigningRequest().toByteArray())
            .issueCertificate(request);

    CertificateFactory cf = CertificateFactory.getInstance("X.509");

    assertEquals(2, response.getSignedCertificatesCount());

    X509Certificate signedCert =
        (X509Certificate)
            cf.generateCertificate(
                new ByteArrayInputStream(response.getSignedCertificates(0).toByteArray()));

    X509Certificate rootCert = injector.getInstance(X509Certificate.class);

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

    String expectedSpiffeId =
        "spiffe://example.org.tca.local.test/operator/example.org/test_operator_role/publisher/google.com/pcit-release-bot/workload/"
            + goldenRequest.getWorkloadId();

    // Verify the SAN extension
    GeneralNames names =
        GeneralNames.getInstance(
            ASN1OctetString.getInstance(
                    signedCert.getExtensionValue(Extension.subjectAlternativeName.getId()))
                .getOctets());
    GeneralName sanEntry = names.getNames()[0];
    assertThat(sanEntry.getTagNo()).isEqualTo(GeneralName.uniformResourceIdentifier);
    assertThat(sanEntry.getName().toString()).isEqualTo(expectedSpiffeId);

    // Verify the Name Constraints extension
    byte[] nameConstraintsBytes = signedCert.getExtensionValue(Extension.nameConstraints.getId());
    assertThat(nameConstraintsBytes).isNotNull();

    try (ASN1InputStream is = new ASN1InputStream(new ByteArrayInputStream(nameConstraintsBytes))) {
      ASN1OctetString octetString = (ASN1OctetString) is.readObject();
      NameConstraints nameConstraints = NameConstraints.getInstance(octetString.getOctets());

      GeneralSubtree[] permitted = nameConstraints.getPermittedSubtrees();
      assertThat(permitted).hasLength(2);
      GeneralName generalName1 = permitted[0].getBase();
      assertThat(generalName1.getTagNo()).isEqualTo(GeneralName.uniformResourceIdentifier);
      String suffix = policyPath.contains("/v2/") ? ".tca.local.test" : "";
      assertThat(generalName1.getName().toString()).isEqualTo(".example1.org" + suffix);
      GeneralName generalName2 = permitted[1].getBase();
      assertThat(generalName2.getTagNo()).isEqualTo(GeneralName.uniformResourceIdentifier);
      assertThat(generalName2.getName().toString()).isEqualTo(".example2.org" + suffix);
    }

    // Verify the Basic Constraints extension
    BasicConstraints basicConstraints =
        BasicConstraints.getInstance(
            ASN1OctetString.getInstance(
                    signedCert.getExtensionValue(Extension.basicConstraints.getId()))
                .getOctets());
    assertThat(basicConstraints.isCA()).isTrue();
    assertThat(basicConstraints.getPathLenConstraint().intValue()).isEqualTo(1);

    // Verify metrics are collected and exposed
    AggregatedHttpResponse res = httpClient.get("/metrics").aggregate().join();
    assertThat(res.status()).isEqualTo(HttpStatus.OK);
    assertThat(res.contentUtf8()).contains("tca_server_total_duration_seconds");
    assertThat(res.contentUtf8()).contains("tca_server_response_length");
  }

  @Test
  public void issueCertificate_validRequest_fails_when_missing_policy_file() throws Exception {

    GoldenRequest goldenRequest = new GoldenRequest();
    IssueCertificateRequest request = goldenRequest.getRequestBody();

    TransparentCertificateAuthorityGrpc.TransparentCertificateAuthorityBlockingStub authStub =
        withTokenForCsr(request.getCertificateSigningRequest().toByteArray());
    StatusRuntimeException thrown =
        assertThrows(StatusRuntimeException.class, () -> authStub.issueCertificate(request));
    assertEquals(Status.Code.INVALID_ARGUMENT, thrown.getStatus().getCode());
    assertThat(thrown.getStatus().getDescription())
        .contains("No policy supports requested workload");
  }

  @Test
  public void metricsEndpoint_returnsPrometheusMetrics() {
    AggregatedHttpResponse res = httpClient.get("/metrics").aggregate().join();
    assertThat(res.status()).isEqualTo(HttpStatus.OK);
    assertThat(res.contentUtf8()).contains("armeria_server_connections");
    assertThat(res.contentUtf8()).contains("jvm_memory_used_bytes");
    assertThat(res.contentUtf8()).contains("jvm_threads_live_threads");
    assertThat(res.contentUtf8()).contains("process_cpu_usage");
    assertThat(res.contentUtf8()).contains("system_cpu_usage");
  }

  @Test
  public void customMetrics_collectedAndExposed_succeeds() {
    Metrics metrics = injector.getInstance(Metrics.class);

    // Initially, both metric arrays should be registered and present in scrape with 0.0 values
    AggregatedHttpResponse initialRes = httpClient.get("/metrics").aggregate().join();
    assertThat(initialRes.status()).isEqualTo(HttpStatus.OK);
    assertThat(initialRes.contentUtf8())
        .contains("tca_authenticationStatus_total{status=\"success\"} 0.0");
    assertThat(initialRes.contentUtf8())
        .contains("tca_authenticationStatus_total{status=\"failure\"} 0.0");
    assertThat(initialRes.contentUtf8())
        .contains("tca_processingStatus_total{status=\"success\"} 0.0");
    assertThat(initialRes.contentUtf8())
        .contains("tca_processingStatus_total{status=\"missing_policy\"} 0.0");
    assertThat(initialRes.contentUtf8())
        .contains("tca_processingStatus_total{status=\"policy_identity_mismatch\"} 0.0");

    // Increment specific targets
    metrics.incrementAuthenticationCounter(com.google.tca.domain.metric.Status.SUCCESS);
    metrics.incrementProcessingCounter(ProcessingStatus.SUCCESS);

    // Verify targeted indices are incremented while others remain at 0.0
    AggregatedHttpResponse res = httpClient.get("/metrics").aggregate().join();
    assertThat(res.status()).isEqualTo(HttpStatus.OK);
    assertThat(res.contentUtf8())
        .contains("tca_authenticationStatus_total{status=\"success\"} 1.0");
    assertThat(res.contentUtf8())
        .contains("tca_authenticationStatus_total{status=\"failure\"} 0.0");
    assertThat(res.contentUtf8()).contains("tca_processingStatus_total{status=\"success\"} 1.0");
    assertThat(res.contentUtf8())
        .contains("tca_processingStatus_total{status=\"missing_policy\"} 0.0");
    assertThat(res.contentUtf8())
        .contains("tca_processingStatus_total{status=\"policy_identity_mismatch\"} 0.0");
  }

  @Test
  public void customMetrics_metadataAndTypeExposed_succeeds() {
    // Force instantiation to trigger constructor metrics registration
    injector.getInstance(Metrics.class);

    AggregatedHttpResponse res = httpClient.get("/metrics").aggregate().join();
    assertThat(res.status()).isEqualTo(HttpStatus.OK);

    // Verify HELP metadata headers
    assertThat(res.contentUtf8())
        .contains(
            "# HELP tca_authenticationStatus_total Metrics tracking for tca.authenticationStatus");
    assertThat(res.contentUtf8())
        .contains("# HELP tca_processingStatus_total Metrics tracking for tca.processingStatus");

    // Verify TYPE metadata headers
    assertThat(res.contentUtf8()).contains("# TYPE tca_authenticationStatus_total counter");
    assertThat(res.contentUtf8()).contains("# TYPE tca_processingStatus_total counter");

    // Verify raw initial value line format
    assertThat(res.contentUtf8())
        .contains("tca_authenticationStatus_total{status=\"success\"} 0.0");
    assertThat(res.contentUtf8())
        .contains("tca_authenticationStatus_total{status=\"failure\"} 0.0");
    assertThat(res.contentUtf8()).contains("tca_processingStatus_total{status=\"success\"} 0.0");
    assertThat(res.contentUtf8())
        .contains("tca_processingStatus_total{status=\"missing_policy\"} 0.0");
    assertThat(res.contentUtf8())
        .contains("tca_processingStatus_total{status=\"policy_identity_mismatch\"} 0.0");
  }

  @Test
  public void issueCertificate_fails_when_policy_identity_mismatched() throws Exception {
    GoldenRequest goldenRequest = new GoldenRequest();
    uploadMismatchedPolicyToS3(goldenRequest.getPublisherId(), goldenRequest.getWorkloadId());

    Instant testTime =
        goldenRequest.getNotBefore().plusSeconds(10000).truncatedTo(ChronoUnit.SECONDS);
    IssueCertificateRequest request = goldenRequest.getRequestBody();

    when(timeProvider.currentTimeMillis()).thenReturn(testTime.toEpochMilli());
    when(timeProvider.now()).thenReturn(Instant.ofEpochMilli(testTime.toEpochMilli()));

    StatusRuntimeException thrown =
        assertThrows(
            StatusRuntimeException.class,
            () ->
                withTokenForCsr(request.getCertificateSigningRequest().toByteArray())
                    .issueCertificate(request));
    assertEquals(Status.Code.INVALID_ARGUMENT, thrown.getStatus().getCode());
    assertThat(thrown.getStatus().getDescription()).contains("Policy identity mismatch");

    AggregatedHttpResponse res = httpClient.get("/metrics").aggregate().join();
    assertThat(res.status()).isEqualTo(HttpStatus.OK);
    assertThat(res.contentUtf8())
        .contains("tca_processingStatus_total{status=\"policy_identity_mismatch\"} 1.0");
  }

  private static String readTestFile(String path) throws Exception {
    return Files.readString(Paths.get(path));
  }

  private void uploadFileToS3(String key, String content) throws Exception {
    s3Client.putObject(
        PutObjectRequest.builder().bucket(BUCKET_NAME).key(key).build(),
        RequestBody.fromString(content));
  }

  private void uploadPolicyToS3(String publisher_id, String workload_id) throws Exception {
    String policy = readTestFile(policyPath);
    String oakContainersReferenceValues =
        readTestFile("javatests/com/google/tca/server/testdata/reference_values.textproto");
    policy =
        policy
            .replace("{publisher_id_to_replace}", publisher_id)
            .replace("{workload_id_to_replace}", workload_id)
            .replace("{oak_containers_reference_values}", oakContainersReferenceValues);
    uploadFileToS3("https_003a_002f_002faccounts.google.com/jwt-token-test-sub", policy);
  }

  private void uploadMismatchedPolicyToS3(String publisher_id, String workload_id)
      throws Exception {
    String policy =
        readTestFile("javatests/com/google/tca/server/testdata/policy/v1/policy.textproto");
    String oakContainersReferenceValues =
        readTestFile("javatests/com/google/tca/server/testdata/reference_values.textproto");
    policy =
        policy
            .replace("{publisher_id_to_replace}", publisher_id)
            .replace("{workload_id_to_replace}", workload_id)
            .replace("{oak_containers_reference_values}", oakContainersReferenceValues)
            .replace("jwt-token-test-sub", "mismatched-sub");
    uploadFileToS3("https_003a_002f_002faccounts.google.com/jwt-token-test-sub", policy);
  }
}
