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

import com.google.common.flogger.FluentLogger;
import com.google.mbs.Metrics.MbsEvent;
import com.google.tca.domain.metric.Metrics;
import com.google.tca.domain.metric.ProcessingStatus;
import com.google.tca.domain.metric.Status;
import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Gauge;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;

@Singleton
public class SystemMetrics implements Metrics, com.google.mbs.Metrics {

  private static final FluentLogger logger = FluentLogger.forEnclosingClass();
  private static final String PREFIX = "tca.";
  private static final int MAX_APPROVED_CLIENTS = 1000;

  private final PrometheusMeterRegistry registry;
  private final Counter[] authenticationCounter;
  private final Counter[] processingCounter;
  private final AtomicInteger[] mbsStatusValues;
  private final Set<String> approvedClients = ConcurrentHashMap.newKeySet();
  private final ConcurrentHashMap<String, Counter> issuanceCounters = new ConcurrentHashMap<>();
  private final AtomicLong rootCertificateValiditySeconds = new AtomicLong(0);
  private final AtomicBoolean rootCertificateValiditySecondsRegistered = new AtomicBoolean(false);

  @Inject
  public SystemMetrics(PrometheusMeterRegistry registry) {
    this.registry = registry;
    this.authenticationCounter =
        createCounters(PREFIX + "authenticationStatus", "status", Status.class);
    this.processingCounter =
        createCounters(PREFIX + "processingStatus", "status", ProcessingStatus.class);
    this.mbsStatusValues = createGauges(PREFIX + "mbsStatus", "status", MbsEvent.class);
  }

  private <E extends Enum<E>> Counter[] createCounters(
      String name, String tagKey, Class<E> enumClass) {
    E[] constants = enumClass.getEnumConstants();
    Counter[] array = new Counter[constants.length];
    for (E item : constants) {
      array[item.ordinal()] =
          Counter.builder(name)
              .tag(tagKey, item.name().toLowerCase())
              .description("Metrics tracking for " + name)
              .register(registry);
    }
    return array;
  }

  private <E extends Enum<E>> AtomicInteger[] createGauges(
      String name, String tagKey, Class<E> enumClass) {
    E[] constants = enumClass.getEnumConstants();
    AtomicInteger[] array = new AtomicInteger[constants.length];
    for (E item : constants) {
      array[item.ordinal()] = new AtomicInteger(0);
      Gauge.builder(name, array[item.ordinal()], AtomicInteger::get)
          .tag(tagKey, item.name().toLowerCase())
          .description("Metrics tracking for " + name)
          .register(registry);
    }
    return array;
  }

  @Override
  public void incrementAuthenticationCounter(Status status) {
    if (status != null) {
      authenticationCounter[status.ordinal()].increment();
    }
  }

  @Override
  public void incrementProcessingCounter(ProcessingStatus status) {
    if (status != null) {
      processingCounter[status.ordinal()].increment();
    }
  }

  @Override
  public void allowMetricsForClientId(String clientId) {
    if (approvedClients.contains(clientId)) {
      return;
    }
    synchronized (this) {
      if (approvedClients.contains(clientId)) {
        return;
      }
      if (approvedClients.size() < MAX_APPROVED_CLIENTS) {
        approvedClients.add(clientId);
      } else {
        logger.atWarning().log(
            "Max approved clients limit (%d) reached. Rejecting client: %s",
            MAX_APPROVED_CLIENTS, clientId);
      }
    }
  }

  @Override
  public void incrementCertificateIssuanceCounter(String clientId) {
    if (clientId != null && approvedClients.contains(clientId)) {
      issuanceCounters
          .computeIfAbsent(
              clientId,
              id ->
                  Counter.builder(PREFIX + "certificateIssuance")
                      .tag("client_id", id)
                      .description("Number of certificates issued per client")
                      .register(registry))
          .increment();
    }
  }

  @Override
  public void recordEvent(MbsEvent event) {
    if (event != null) {
      for (MbsEvent e : MbsEvent.class.getEnumConstants()) {
        mbsStatusValues[e.ordinal()].set(e == event ? 1 : 0);
      }
    }
  }

  @Override
  public void setRootCertificateValidity(Duration remaining) {
    rootCertificateValiditySeconds.set(remaining.toSeconds());
    if (rootCertificateValiditySecondsRegistered.compareAndSet(false, true)) {
      Gauge.builder(
              PREFIX + "root_certificate_validity_seconds",
              rootCertificateValiditySeconds,
              AtomicLong::get)
          .description("Seconds remaining until the root certificate expires")
          .register(registry);
    }
  }
}
