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

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.tca.domain.TimeProvider;
import com.google.tca.domain.metric.Metrics;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

@RunWith(JUnit4.class)
public class CertificateValidityReporterTest {

  @Rule public final MockitoRule mockito = MockitoJUnit.rule();

  @Mock private X509Certificate mockCertificate;
  @Mock private Metrics mockMetrics;
  @Mock private TimeProvider mockTimeProvider;

  private CertificateValidityReporter reporter;

  @Before
  public void setUp() {
    reporter = new CertificateValidityReporter(mockCertificate, mockMetrics, mockTimeProvider);
  }

  @Test
  public void runOneIteration_reportsCorrectValidity() throws Exception {
    // Arrange
    Instant now = Instant.parse("2026-06-30T10:00:00Z");
    Instant expiry = now.plus(Duration.ofDays(10));
    when(mockTimeProvider.now()).thenReturn(now);
    when(mockCertificate.getNotAfter()).thenReturn(Date.from(expiry));

    // Act
    reporter.runOneIteration();

    // Assert
    ArgumentCaptor<Duration> durationCaptor = ArgumentCaptor.forClass(Duration.class);
    verify(mockMetrics).setRootCertificateValidity(durationCaptor.capture());
    assertThat(durationCaptor.getValue()).isEqualTo(Duration.ofDays(10));
  }

  @Test
  public void runOneIteration_whenExpired_reportsZero() throws Exception {
    // Arrange
    Instant now = Instant.parse("2026-06-30T10:00:00Z");
    Instant expiry = now.minus(Duration.ofDays(10));
    when(mockTimeProvider.now()).thenReturn(now);
    when(mockCertificate.getNotAfter()).thenReturn(Date.from(expiry));

    // Act
    reporter.runOneIteration();

    // Assert
    verify(mockMetrics).setRootCertificateValidity(Duration.ZERO);
  }
}
