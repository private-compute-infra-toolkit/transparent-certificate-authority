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
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.mbs.domain.MeasurementBoundCertificate;
import com.google.mbs.domain.MeasurementBoundCertificateProvider;
import com.linecorp.armeria.client.WebClient;
import com.linecorp.armeria.common.AggregatedHttpResponse;
import com.linecorp.armeria.common.HttpStatus;
import io.grpc.ServerServiceDefinition;
import io.micrometer.prometheusmetrics.PrometheusConfig;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class TcaServerTest {

  private TransparentCertificateAuthorityGrpcHandler service;
  private TrustedCertificateAuthorityGrpcHandler legacyService;
  private JwtInterceptor jwtInterceptor;
  private PrometheusMeterRegistry meterRegistry;
  private MeasurementBoundCertificateProvider certificateProvider;
  private MeasurementBoundCertificate mockCertificate;
  private TcaServer tcaServer;

  @Before
  public void setUp() {
    service = mock(TransparentCertificateAuthorityGrpcHandler.class);
    when(service.bindService()).thenReturn(ServerServiceDefinition.builder("tca.service").build());

    legacyService = mock(TrustedCertificateAuthorityGrpcHandler.class);
    when(legacyService.bindService())
        .thenReturn(ServerServiceDefinition.builder("legacy.service").build());

    jwtInterceptor = mock(JwtInterceptor.class);
    meterRegistry = new PrometheusMeterRegistry(PrometheusConfig.DEFAULT);
    certificateProvider = mock(MeasurementBoundCertificateProvider.class);
    mockCertificate = mock(MeasurementBoundCertificate.class);
  }

  @After
  public void tearDown() {
    if (tcaServer != null) {
      tcaServer.stop().join();
    }
  }

  @Test
  public void healthCheck_returnsOkWhenServingAndCertificateAvailable() {
    when(certificateProvider.getCertificate()).thenReturn(mockCertificate);

    tcaServer =
        new TcaServer(
            0, service, legacyService, jwtInterceptor, meterRegistry, certificateProvider);
    tcaServer.start().join();

    assertThat(tcaServer.isHealthy()).isTrue();

    WebClient client = WebClient.of("http://127.0.0.1:" + tcaServer.port());
    AggregatedHttpResponse response = client.get("/healthz").aggregate().join();
    assertThat(response.status()).isEqualTo(HttpStatus.OK);
  }

  @Test
  public void healthCheck_returnsServiceUnavailableWhenCertificateThrowsIllegalStateException() {
    when(certificateProvider.getCertificate())
        .thenThrow(
            new IllegalStateException(
                "Measurement-bound certificate has not been initialized yet"));

    tcaServer =
        new TcaServer(
            0, service, legacyService, jwtInterceptor, meterRegistry, certificateProvider);
    tcaServer.start().join();

    assertThat(tcaServer.isHealthy()).isFalse();

    WebClient client = WebClient.of("http://127.0.0.1:" + tcaServer.port());
    AggregatedHttpResponse response = client.get("/healthz").aggregate().join();
    assertThat(response.status()).isEqualTo(HttpStatus.SERVICE_UNAVAILABLE);
  }

  @Test
  public void healthCheck_returnsServiceUnavailableWhenServerStopped() {
    when(certificateProvider.getCertificate()).thenReturn(mockCertificate);

    tcaServer =
        new TcaServer(
            0, service, legacyService, jwtInterceptor, meterRegistry, certificateProvider);
    tcaServer.start().join();
    tcaServer.stop().join();

    assertThat(tcaServer.isHealthy()).isFalse();
  }
}
