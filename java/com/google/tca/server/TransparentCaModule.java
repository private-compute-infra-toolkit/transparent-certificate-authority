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

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableMap;
import com.google.common.flogger.FluentLogger;
import com.google.inject.AbstractModule;
import com.google.inject.Provides;
import com.google.mbs.MeasurementBoundCertificate;
import com.google.mbs.attestationcollection.aws.AwsAttestationModule;
import com.google.tca.adapters.AttestationVerifierProviderImpl;
import com.google.tca.adapters.AwsAttestationEvidence;
import com.google.tca.adapters.CachedFileFetcher;
import com.google.tca.adapters.CertificateSignerImpl;
import com.google.tca.adapters.DefaultTimeProvider;
import com.google.tca.adapters.FileSourcedPolicyProvider;
import com.google.tca.adapters.GcpAttestationEvidence;
import com.google.tca.adapters.KeyDecoderImpl;
import com.google.tca.adapters.OakAttestationEvidence;
import com.google.tca.adapters.PolicyBucket;
import com.google.tca.adapters.S3FileFetcher;
import com.google.tca.adapters.SystemMetrics;
import com.google.tca.adapters.certsigning.CertificateModifiersCreatorImpl;
import com.google.tca.adapters.endorsement.JsonIntotoEndorsementMetadataProvider;
import com.google.tca.adapters.oidc.OidcAudienceBindingValidator;
import com.google.tca.adapters.oidc.OidcDiscoveryFetcher;
import com.google.tca.adapters.oidc.OidcJwksKeyFetcher;
import com.google.tca.adapters.oidc.OidcJwksKeyLocator;
import com.google.tca.attestation.aws.AwsAttestationVerifier;
import com.google.tca.attestation.gcp.GcpAttestation;
import com.google.tca.attestation.gcp.GcpAttestationVerifier;
import com.google.tca.attestation.oak.OakAttestation;
import com.google.tca.attestation.oak.OakAttestationVerifier;
import com.google.tca.domain.AudienceBindingValidator;
import com.google.tca.domain.CertificateModifiersCreator;
import com.google.tca.domain.CertificateSigner;
import com.google.tca.domain.EndorsementMetadataProvider;
import com.google.tca.domain.FileFetcher;
import com.google.tca.domain.KeyDecoder;
import com.google.tca.domain.PolicyProvider;
import com.google.tca.domain.TimeProvider;
import com.google.tca.domain.TrustDomain;
import com.google.tca.domain.TrustDomainExtractor;
import com.google.tca.domain.attestation.AttestationEvidence;
import com.google.tca.domain.attestation.AttestationVerifier;
import com.google.tca.domain.attestation.AttestationVerifierProvider;
import com.google.tca.domain.metric.Metrics;
import com.google.tlog.TlogEntry;
import com.google.tlog.TransparencyLogClient;
import io.jsonwebtoken.Locator;
import io.micrometer.core.instrument.binder.jvm.JvmMemoryMetrics;
import io.micrometer.core.instrument.binder.jvm.JvmThreadMetrics;
import io.micrometer.core.instrument.binder.system.ProcessorMetrics;
import io.micrometer.core.instrument.config.MeterFilter;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import jakarta.inject.Singleton;
import java.net.http.HttpClient;
import java.security.Key;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.InstantSource;
import java.util.Map;
import java.util.Optional;
import software.amazon.awssdk.services.s3.S3Client;

/** Guice module for the TCA service. */
public class TransparentCaModule extends AbstractModule {
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  public TransparentCaModule() {}

  @Override
  protected void configure() {
    bind(InstantSource.class).toInstance(InstantSource.system());
    bind(HttpClient.class).toInstance(HttpClient.newHttpClient());
    bind(AttestationVerifierProvider.class).to(AttestationVerifierProviderImpl.class);
    install(new AwsAttestationModule());
    bind(CertificateSigner.class).to(CertificateSignerImpl.class);
    bind(KeyDecoder.class).to(KeyDecoderImpl.class);
    bind(AttestationVerifier.class)
        .annotatedWith(OakAttestation.class)
        .to(OakAttestationVerifier.class);
    bind(TimeProvider.class).to(DefaultTimeProvider.class);
    bind(PolicyProvider.class).to(FileSourcedPolicyProvider.class);
    bind(EndorsementMetadataProvider.class).to(JsonIntotoEndorsementMetadataProvider.class);
    bind(CertificateModifiersCreator.class).to(CertificateModifiersCreatorImpl.class);
    bind(Metrics.class).to(SystemMetrics.class);
    bind(AudienceBindingValidator.class).to(OidcAudienceBindingValidator.class);
  }

  @Provides
  @Singleton
  public FileFetcher provideFileFetcher(
      S3Client s3Client, @PolicyBucket String bucket, InstantSource instantSource) {
    return new CachedFileFetcher(new S3FileFetcher(s3Client, bucket), instantSource);
  }

  @Provides
  @Singleton
  public TransparencyLogClient provideTransparencyLogClient() {
    return new TransparencyLogClient() {
      @Override
      public TlogEntry recordCertificate(X509Certificate c, PrivateKey k) {
        return new TlogEntry("{\"status\":\"dummy\"}");
      }

      @Override
      public Optional<TlogEntry> getTlogEntryByCertificate(X509Certificate c) {
        return Optional.of(new TlogEntry("{\"status\":\"dummy\"}"));
      }
    };
  }

  @Provides
  @Singleton
  @GcpAttestation
  OidcJwksKeyFetcher provideGcpOidcJwksKeyFetcher(
      InstantSource instantSource,
      HttpClient httpClient,
      ObjectMapper objectMapper,
      Metrics metrics) {
    return new OidcJwksKeyFetcher(
        () -> GcpAttestationVerifier.JWKS_URI, instantSource, httpClient, objectMapper, metrics);
  }

  @Provides
  @Singleton
  @JwtAuth
  Locator<Key> provideJwtKeyLocator(@JwtAuth OidcJwksKeyFetcher jwksKeyFetcher) {
    return new OidcJwksKeyLocator(jwksKeyFetcher, "RS256");
  }

  @Provides
  @Singleton
  @JwtAuth
  OidcJwksKeyFetcher provideOidcJwksKeyFetcher(
      OidcDiscoveryFetcher discoveryFetcher,
      InstantSource instantSource,
      HttpClient httpClient,
      ObjectMapper objectMapper,
      Metrics metrics) {
    return new OidcJwksKeyFetcher(
        () ->
            discoveryFetcher.fetchJwksUri(
                "https://accounts.google.com/.well-known/openid-configuration"),
        instantSource,
        httpClient,
        objectMapper,
        metrics);
  }

  @Provides
  @Singleton
  OidcDiscoveryFetcher provideOidcDiscoveryFetcher(
      HttpClient httpClient, ObjectMapper objectMapper) {
    return new OidcDiscoveryFetcher(httpClient, objectMapper);
  }

  @Provides
  Map<Class<? extends AttestationEvidence>, AttestationVerifier> provideVerifiers(
      GcpAttestationVerifier gcpVerifier,
      AwsAttestationVerifier awsVerifier,
      OakAttestationVerifier oakVerifier) {
    return ImmutableMap.of(
        GcpAttestationEvidence.class, gcpVerifier,
        AwsAttestationEvidence.class, awsVerifier,
        OakAttestationEvidence.class, oakVerifier);
  }

  @Provides
  X509Certificate provideRootCertificate(MeasurementBoundCertificate measurementBoundCertificate) {
    return measurementBoundCertificate.getCertificate();
  }

  @Provides
  PrivateKey providePrivateKey(MeasurementBoundCertificate measurementBoundCertificate) {
    return measurementBoundCertificate.getPrivateKey();
  }

  @Provides
  @Singleton
  public ObjectMapper provideObjectMapper() {
    return new ObjectMapper().disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
  }

  @Provides
  @Singleton
  public PrometheusMeterRegistry providePrometheusMeterRegistry() {
    PrometheusMeterRegistry registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
    registry
        .config()
        .meterFilter(MeterFilter.acceptNameStartsWith("tca."))
        .meterFilter(MeterFilter.acceptNameStartsWith("armeria.server.connections"))
        .meterFilter(MeterFilter.acceptNameStartsWith("jvm."))
        .meterFilter(MeterFilter.acceptNameStartsWith("system."))
        .meterFilter(MeterFilter.acceptNameStartsWith("process."))
        .meterFilter(MeterFilter.deny());
    new JvmMemoryMetrics().bindTo(registry);
    new JvmThreadMetrics().bindTo(registry);
    new ProcessorMetrics().bindTo(registry);
    return registry;
  }

  @Provides
  @Singleton
  @TrustDomain
  String provideTrustDomain(X509Certificate rootCertificate)
      throws java.security.cert.CertificateParsingException, java.net.URISyntaxException {
    return TrustDomainExtractor.extract(rootCertificate);
  }
}
