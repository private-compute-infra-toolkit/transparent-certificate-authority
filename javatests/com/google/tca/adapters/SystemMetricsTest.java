/*
 * Copyright 2026 Google LLC
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

package com.google.tca.adapters;

import static com.google.common.truth.Truth.assertThat;

import com.google.mbs.domain.CrossSignedCertificateId;
import com.google.mbs.domain.Metrics.ConfigEvent;
import com.google.mbs.domain.Metrics.GenerationEvent;
import com.google.mbs.domain.Metrics.LoadEvent;
import com.google.mbs.domain.Metrics.MbsEvent;
import com.google.tca.domain.metric.IssuanceSubOperation;
import com.google.tca.domain.metric.JwksCacheResult;
import com.google.tca.domain.metric.ProcessingStatus;
import com.google.tca.domain.metric.Status;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class SystemMetricsTest {

  private PrometheusMeterRegistry registry;
  private SystemMetrics systemMetrics;

  @Before
  public void setUp() {
    registry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
    systemMetrics = new SystemMetrics(registry);
  }

  @Test
  public void constructor_preRegistersAllCountersWithZeroValue() {
    for (Status status : Status.values()) {
      double value =
          registry
              .get("tca.authenticationStatus")
              .tag("status", status.name().toLowerCase())
              .counter()
              .count();
      assertThat(value).isEqualTo(0.0);
    }

    for (ProcessingStatus status : ProcessingStatus.values()) {
      double value =
          registry
              .get("tca.processingStatus")
              .tag("status", status.name().toLowerCase())
              .counter()
              .count();
      assertThat(value).isEqualTo(0.0);
    }

    for (JwksCacheResult result : JwksCacheResult.values()) {
      double value =
          registry
              .get("tca.oidc_jwks_cache_lookups")
              .tag("result", result.name().toLowerCase())
              .counter()
              .count();
      assertThat(value).isEqualTo(0.0);
    }

    for (IssuanceSubOperation op : IssuanceSubOperation.values()) {
      double count =
          registry
              .get("tca.issuance_operation_time")
              .tag("operation", op.name().toLowerCase())
              .timer()
              .count();
      assertThat(count).isEqualTo(0.0);
    }

    for (MbsEvent event : MbsEvent.values()) {
      double value =
          registry.get("tca.mbsStatus").tag("status", event.name().toLowerCase()).gauge().value();
      assertThat(value).isEqualTo(0.0);
    }

    for (GenerationEvent event : GenerationEvent.values()) {
      double value =
          registry
              .get("tca.mbsGenerationStatus")
              .tag("status", event.name().toLowerCase())
              .gauge()
              .value();
      assertThat(value).isEqualTo(0.0);
    }

    for (LoadEvent event : LoadEvent.values()) {
      double value =
          registry
              .get("tca.mbsLoadStatus")
              .tag("status", event.name().toLowerCase())
              .gauge()
              .value();
      assertThat(value).isEqualTo(0.0);
    }

    for (ConfigEvent event : ConfigEvent.values()) {
      double value =
          registry
              .get("tca.mbsConfigStatus")
              .tag("status", event.name().toLowerCase())
              .gauge()
              .value();
      assertThat(value).isEqualTo(0.0);
    }
  }

  @Test
  public void incrementAuthenticationCounter_succeeds() {
    systemMetrics.incrementAuthenticationCounter(Status.SUCCESS);
    systemMetrics.incrementAuthenticationCounter(Status.SUCCESS);
    systemMetrics.incrementAuthenticationCounter(Status.FAILURE);

    double successVal =
        registry.get("tca.authenticationStatus").tag("status", "success").counter().count();
    double failureVal =
        registry.get("tca.authenticationStatus").tag("status", "failure").counter().count();

    assertThat(successVal).isEqualTo(2.0);
    assertThat(failureVal).isEqualTo(1.0);
  }

  @Test
  public void incrementProcessingCounter_succeeds() {
    systemMetrics.incrementProcessingCounter(ProcessingStatus.MISSING_POLICY);
    systemMetrics.incrementProcessingCounter(ProcessingStatus.SUCCESS);
    systemMetrics.incrementProcessingCounter(ProcessingStatus.SUCCESS);

    double missingPolicyVal =
        registry.get("tca.processingStatus").tag("status", "missing_policy").counter().count();
    double successVal =
        registry.get("tca.processingStatus").tag("status", "success").counter().count();

    assertThat(missingPolicyVal).isEqualTo(1.0);
    assertThat(successVal).isEqualTo(2.0);
  }

  @Test
  public void increment_nullInputs_safelyIgnored() {
    systemMetrics.incrementAuthenticationCounter(null);
    systemMetrics.incrementProcessingCounter(null);

    double successA =
        registry.get("tca.authenticationStatus").tag("status", "success").counter().count();
    double successB =
        registry.get("tca.processingStatus").tag("status", "success").counter().count();

    assertThat(successA).isEqualTo(0.0);
    assertThat(successB).isEqualTo(0.0);
  }

  @Test
  public void incrementCertificateIssuanceCounter_approvedClient_succeeds() {
    String clientId = "approved-client";
    systemMetrics.allowMetricsForClientId(clientId);
    systemMetrics.incrementCertificateIssuanceCounter(clientId);
    systemMetrics.incrementCertificateIssuanceCounter(clientId);

    double value =
        registry.get("tca.certificateIssuance").tag("client_id", clientId).counter().count();
    assertThat(value).isEqualTo(2.0);
  }

  @Test
  public void incrementCertificateIssuanceCounter_unapprovedClient_ignored() {
    String clientId = "unapproved-client";
    systemMetrics.incrementCertificateIssuanceCounter(clientId);

    assertThat(registry.find("tca.certificateIssuance").tag("client_id", clientId).counter())
        .isNull();
  }

  @Test
  public void allowMetricsForClient_Id_exceedLimit_ignored() {
    for (int i = 0; i < 1000; i++) {
      systemMetrics.allowMetricsForClientId("client-" + i);
    }
    // 1001st client
    systemMetrics.allowMetricsForClientId("client-1000");

    // Verify first 1000 are approved and can be incremented
    for (int i = 0; i < 1000; i++) {
      systemMetrics.incrementCertificateIssuanceCounter("client-" + i);
      assertThat(registry.find("tca.certificateIssuance").tag("client_id", "client-" + i).counter())
          .isNotNull();
    }
    // Verify 1001st is NOT approved
    systemMetrics.incrementCertificateIssuanceCounter("client-1000");
    assertThat(registry.find("tca.certificateIssuance").tag("client_id", "client-1000").counter())
        .isNull();
  }

  @Test
  public void setRootCertificateValidity_registersGaugeOnFirstCall() {
    assertThat(registry.find("tca.root_certificate_validity_seconds").gauge()).isNull();

    systemMetrics.setRootCertificateValidity(Duration.ofMinutes(5));

    Gauge gauge = registry.get("tca.root_certificate_validity_seconds").gauge();
    assertThat(gauge).isNotNull();
    assertThat(gauge.value()).isEqualTo(300.0);

    systemMetrics.setRootCertificateValidity(Duration.ofMinutes(10));
    assertThat(gauge.value()).isEqualTo(600.0);
  }

  @Test
  public void recordOidcJwksLookupAndMiss_succeeds() {
    systemMetrics.recordOidcJwksLookup();
    systemMetrics.recordOidcJwksLookup();
    systemMetrics.recordOidcJwksMiss();

    double totalVal =
        registry.get("tca.oidc_jwks_cache_lookups").tag("result", "total").counter().count();
    double missVal =
        registry.get("tca.oidc_jwks_cache_lookups").tag("result", "miss").counter().count();

    assertThat(totalVal).isEqualTo(2.0);
    assertThat(missVal).isEqualTo(1.0);
  }

  @Test
  public void recordOidcJwksFetchTime_succeeds() {
    systemMetrics.recordOidcJwksFetchTime(Duration.ofMillis(150));

    double count = registry.get("tca.oidc_jwks_fetch_time").timer().count();
    double totalTimeSecs =
        registry.get("tca.oidc_jwks_fetch_time").timer().totalTime(TimeUnit.SECONDS);

    assertThat(count).isEqualTo(1.0);
    assertThat(totalTimeSecs).isWithin(0.01).of(0.150);
  }

  @Test
  public void recordOidcAuthenticationTime_succeeds() {
    systemMetrics.recordOidcAuthenticationTime(Duration.ofMillis(120));

    double count = registry.get("tca.oidc_authentication_time").timer().count();
    double totalTimeSecs =
        registry.get("tca.oidc_authentication_time").timer().totalTime(TimeUnit.SECONDS);

    assertThat(count).isEqualTo(1.0);
    assertThat(totalTimeSecs).isWithin(0.01).of(0.120);
  }

  @Test
  public void recordIssuanceSubOperationTime_succeeds() {
    systemMetrics.recordIssuanceSubOperationTime(
        IssuanceSubOperation.VERIFY_ATTESTATION, Duration.ofMillis(150));

    double count =
        registry
            .get("tca.issuance_operation_time")
            .tag("operation", "verify_attestation")
            .timer()
            .count();
    double totalTimeSecs =
        registry
            .get("tca.issuance_operation_time")
            .tag("operation", "verify_attestation")
            .timer()
            .totalTime(TimeUnit.SECONDS);

    assertThat(count).isEqualTo(1.0);
    assertThat(totalTimeSecs).isWithin(0.01).of(0.150);
  }

  @Test
  public void recordMbsEvents_updatesExclusiveStateGauges() {
    systemMetrics.recordGenerationEvent(GenerationEvent.KMS_OPERATION_FAILED);
    assertThat(
            registry
                .get("tca.mbsGenerationStatus")
                .tag("status", "kms_operation_failed")
                .gauge()
                .value())
        .isEqualTo(1.0);
    assertThat(registry.get("tca.mbsGenerationStatus").tag("status", "success").gauge().value())
        .isEqualTo(0.0);

    systemMetrics.recordGenerationEvent(GenerationEvent.SUCCESS);
    assertThat(
            registry
                .get("tca.mbsGenerationStatus")
                .tag("status", "kms_operation_failed")
                .gauge()
                .value())
        .isEqualTo(0.0);
    assertThat(registry.get("tca.mbsGenerationStatus").tag("status", "success").gauge().value())
        .isEqualTo(1.0);

    systemMetrics.recordLoadEvent(LoadEvent.BACKUP_NOT_FOUND);
    assertThat(registry.get("tca.mbsLoadStatus").tag("status", "backup_not_found").gauge().value())
        .isEqualTo(1.0);
    assertThat(registry.get("tca.mbsLoadStatus").tag("status", "success").gauge().value())
        .isEqualTo(0.0);

    systemMetrics.recordConfigEvent(ConfigEvent.INVALID_CONFIGURATION_FILE);
    assertThat(
            registry
                .get("tca.mbsConfigStatus")
                .tag("status", "invalid_configuration_file")
                .gauge()
                .value())
        .isEqualTo(1.0);
    assertThat(registry.get("tca.mbsConfigStatus").tag("status", "success").gauge().value())
        .isEqualTo(0.0);

    String prometheusScrape = registry.scrape();
    assertThat(prometheusScrape).contains("tca_mbsGenerationStatus{status=\"success\"} 1.0");
    assertThat(prometheusScrape).contains("tca_mbsLoadStatus{status=\"backup_not_found\"} 1.0");
    assertThat(prometheusScrape)
        .contains("tca_mbsConfigStatus{status=\"invalid_configuration_file\"} 1.0");
  }

  @Test
  public void recordActiveSelfSignedCertificates_reportsOnlyMostRecentValues() {
    String metric = "tca.mbsActiveSelfSignedCertificate";

    systemMetrics.recordActiveSelfSignedCertificates(Set.of(0, 1));
    assertThat(activeEpochGauges(metric)).containsExactly("0", 1.0, "1", 1.0);

    systemMetrics.recordActiveSelfSignedCertificates(Set.of(1, 2));
    assertThat(activeEpochGauges(metric)).containsExactly("1", 1.0, "2", 1.0);
  }

  @Test
  public void recordActiveCrossSignedCertificates_reportsOnlyMostRecentValues() {
    String metric = "tca.mbsActiveCrossSignedCertificate";
    CrossSignedCertificateId cert01 = new CrossSignedCertificateId(0, 1);
    CrossSignedCertificateId cert10 = new CrossSignedCertificateId(1, 0);
    CrossSignedCertificateId cert12 = new CrossSignedCertificateId(1, 2);

    systemMetrics.recordActiveCrossSignedCertificates(Set.of(cert01, cert10));
    assertThat(activeEpochGauges(metric)).containsExactly("0_1", 1.0, "1_0", 1.0);

    systemMetrics.recordActiveCrossSignedCertificates(Set.of(cert10, cert12));
    assertThat(activeEpochGauges(metric)).containsExactly("1_0", 1.0, "1_2", 1.0);
  }

  @Test
  public void recordActiveSelfSignedCertificates_capsLifetimeTagCount() {
    int retired = SystemMetrics.MAX_ACTIVE_CERTIFICATE_TAGS - 10;
    systemMetrics.recordActiveSelfSignedCertificates(epochs(0, retired));

    systemMetrics.recordActiveSelfSignedCertificates(epochs(retired, retired + 50));

    Map<String, Double> active = activeEpochGauges("tca.mbsActiveSelfSignedCertificate");
    assertThat(active).hasSize(10);
    assertThat(active.values()).containsExactlyElementsIn(Collections.nCopies(10, 1.0));
  }

  @Test
  public void recordActiveCrossSignedCertificates_capsLifetimeTagCount() {
    int retired = SystemMetrics.MAX_ACTIVE_CERTIFICATE_TAGS - 10;
    systemMetrics.recordActiveCrossSignedCertificates(crossSignedCerts(0, retired));

    systemMetrics.recordActiveCrossSignedCertificates(crossSignedCerts(retired, retired + 50));

    Map<String, Double> active = activeEpochGauges("tca.mbsActiveCrossSignedCertificate");
    assertThat(active).hasSize(10);
    assertThat(active.values()).containsExactlyElementsIn(Collections.nCopies(10, 1.0));
  }

  private static Set<Integer> epochs(int startInclusive, int endExclusive) {
    return IntStream.range(startInclusive, endExclusive).boxed().collect(Collectors.toSet());
  }

  private static Set<CrossSignedCertificateId> crossSignedCerts(
      int startInclusive, int endExclusive) {
    return IntStream.range(startInclusive, endExclusive)
        .mapToObj(i -> new CrossSignedCertificateId(0, i + 1))
        .collect(Collectors.toSet());
  }

  private Map<String, Double> activeEpochGauges(String metricName) {
    return registry.find(metricName).gauges().stream()
        .collect(Collectors.toMap(g -> g.getId().getTag("epoch"), Gauge::value));
  }
}
