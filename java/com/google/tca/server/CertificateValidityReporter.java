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

package com.google.tca.server;

import com.google.common.flogger.FluentLogger;
import com.google.common.util.concurrent.AbstractScheduledService;
import com.google.mbs.domain.MeasurementBoundCertificateProvider;
import com.google.tca.domain.TimeProvider;
import com.google.tca.domain.metric.Metrics;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;

/** Reports the validity of the root TCA certificate to the Metrics system. */
@Singleton
public class CertificateValidityReporter extends AbstractScheduledService {
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  private final MeasurementBoundCertificateProvider certificateProvider;
  private final Metrics metrics;
  private final TimeProvider timeProvider;

  @Inject
  public CertificateValidityReporter(
      MeasurementBoundCertificateProvider certificateProvider,
      Metrics metrics,
      TimeProvider timeProvider) {
    this.certificateProvider = certificateProvider;
    this.metrics = metrics;
    this.timeProvider = timeProvider;
  }

  @Override
  protected void runOneIteration() {
    try {
      X509Certificate certificate = certificateProvider.getCertificate().getCertificate();
      Instant expiry = certificate.getNotAfter().toInstant();
      Instant now = timeProvider.now();
      Duration remaining = Duration.between(now, expiry);
      // Ensure we don't report negative validity if it's expired
      if (remaining.isNegative()) {
        remaining = Duration.ZERO;
      }
      metrics.setRootCertificateValidity(remaining);
      logger.atInfo().log(
          "Reported certificate validity metric: %d seconds remaining", remaining.toSeconds());
    } catch (Exception e) {
      logger.atSevere().withCause(e).log("Failed to update certificate validity metric");
    }
  }

  @Override
  protected Scheduler scheduler() {
    // Stagger startup by 30 seconds to allow CertificateMonitor to complete the initial
    // load/generation
    // and ensure steady-state reporting runs shortly after periodic 10-minute reloads.
    return Scheduler.newFixedRateSchedule(Duration.ofSeconds(30), Duration.ofMinutes(10));
  }
}
