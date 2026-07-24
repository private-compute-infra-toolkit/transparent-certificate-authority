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

import com.fasterxml.jackson.core.JsonLocation;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.flogger.FluentLogger;
import com.linecorp.armeria.common.AggregatedHttpRequest;
import com.linecorp.armeria.common.AggregatedHttpResponse;
import com.linecorp.armeria.common.HttpResponse;
import com.linecorp.armeria.common.HttpStatus;
import com.linecorp.armeria.common.grpc.GrpcMeterIdPrefixFunction;
import com.linecorp.armeria.server.HttpService;
import com.linecorp.armeria.server.Server;
import com.linecorp.armeria.server.ServiceRequestContext;
import com.linecorp.armeria.server.grpc.GrpcService;
import com.linecorp.armeria.server.logging.LoggingService;
import com.linecorp.armeria.server.metric.MetricCollectingService;
import com.linecorp.armeria.server.prometheus.PrometheusExpositionService;
import io.grpc.ServerInterceptors;
import io.grpc.health.v1.HealthCheckResponse.ServingStatus;
import io.grpc.protobuf.services.HealthStatusManager;
import io.grpc.protobuf.services.ProtoReflectionService;
import io.micrometer.prometheusmetrics.PrometheusMeterRegistry;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;

/** An Armeria server that hosts the TransparentCaService with gRPC and REST support. */
public class TcaServer {
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();
  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

  private final Server server;
  private final HealthManager healthManager;
  private final int port;

  public TcaServer(
      int port,
      TransparentCertificateAuthorityGrpcHandler service,
      TrustedCertificateAuthorityGrpcHandler legacyService,
      JwtInterceptor jwtInterceptor,
      PrometheusMeterRegistry meterRegistry) {
    this.port = port;
    this.healthManager = new HealthManager();

    final GrpcService grpcService =
        GrpcService.builder()
            .addService(ServerInterceptors.intercept(service, jwtInterceptor))
            .addService(ServerInterceptors.intercept(legacyService, jwtInterceptor))
            .addService(ProtoReflectionService.newInstance())
            .addService(healthManager.getGrpcHealthService())
            .enableHttpJsonTranscoding(true)
            .useBlockingTaskExecutor(true)
            // Offload blocking gRPC calls to prevent EventLoop starvation.
            .build();

    this.server =
        Server.builder()
            .http(port)
            .meterRegistry(meterRegistry)
            .blockingTaskExecutor(100)
            .service(
                grpcService,
                MetricCollectingService.newDecorator(GrpcMeterIdPrefixFunction.of("tca.server")),
                createErrorLoggingDecorator())
            .service(
                "/healthz",
                (ctx, req) -> {
                  if (healthManager.isServing()) {
                    return HttpResponse.of(HttpStatus.OK);
                  }
                  return HttpResponse.of(HttpStatus.SERVICE_UNAVAILABLE);
                })
            .service(
                "/metrics", PrometheusExpositionService.of(meterRegistry.getPrometheusRegistry()))
            .decorator(LoggingService.newDecorator())
            .build();
  }

  private static Function<HttpService, HttpService> createErrorLoggingDecorator() {
    return delegate ->
        (ctx, req) ->
            HttpResponse.from(
                req.aggregate()
                    .thenApply(
                        aggregatedReq -> {
                          try {
                            HttpResponse res = delegate.serve(ctx, aggregatedReq.toHttpRequest());
                            return HttpResponse.from(
                                res.aggregate()
                                    .handle(
                                        (aggregatedRes, cause) ->
                                            handleResponseAndLogOnError(
                                                ctx, aggregatedReq, aggregatedRes, cause)));
                          } catch (Exception e) {
                            return HttpResponse.ofFailure(e);
                          }
                        }));
  }

  private static HttpResponse handleResponseAndLogOnError(
      ServiceRequestContext ctx,
      AggregatedHttpRequest aggregatedReq,
      AggregatedHttpResponse aggregatedRes,
      Throwable cause) {
    boolean isError =
        (aggregatedRes != null && aggregatedRes.status().code() >= 400) || cause != null;

    if (isError) {
      logErrorDetails(ctx, aggregatedReq, aggregatedRes, cause);
    }

    if (cause != null) {
      return HttpResponse.ofFailure(cause);
    }
    return aggregatedRes.toHttpResponse();
  }

  private static void logErrorDetails(
      ServiceRequestContext ctx,
      AggregatedHttpRequest aggregatedReq,
      AggregatedHttpResponse aggregatedRes,
      Throwable cause) {
    String body = aggregatedReq.contentUtf8();
    String status =
        aggregatedRes != null ? aggregatedRes.status().toString() : "Unknown (Exception)";

    StringBuilder logMessage = new StringBuilder();
    // Sanitize and truncate the body to avoid bloating logs and binary blobs.
    String sanitizedBody = sanitizeForLogging(body, 2048);
    logMessage.append(
        String.format(
            "[==== Log message START ====]\n"
                + " Request to %s failed with %s. \n"
                + "Request body length: %d. \n"
                + "Request body (sanitized/truncated): %s",
            ctx.path(), status, body.length(), sanitizedBody));

    if (cause != null) {
      logMessage.append("\nCause: ").append(cause.getMessage());
    }

    // Try to parse the body to extract exact JSON parse error if it's an error.
    // This helps debugging even if the error wasn't initially identified as a BAD_REQUEST.
    if (!body.isEmpty()) {
      try {
        OBJECT_MAPPER.readTree(body);
      } catch (JsonParseException e) {
        logMessage.append("\nJSON parse error: ").append(e.getMessage());
        JsonLocation loc = e.getLocation();
        if (loc != null) {
          long offset = loc.getCharOffset();
          if (offset >= 0 && offset <= body.length()) {
            int start = (int) Math.max(0, offset - 50);
            int end = (int) Math.min(body.length(), offset + 50);
            String snippet = body.substring(start, end);
            logMessage.append(
                String.format(
                    "\nRequest body: Error context around offset %d: ...%s...",
                    offset, sanitizeForLogging(snippet, snippet.length())));
          }
        }
      } catch (Exception e) {
        // Ignore other errors here, we only care about Jackson parse exceptions
      }
    }

    logger.atWarning().log("%s \n[==== Log message END ====]", logMessage.toString());
  }

  private static String sanitizeForLogging(String input, int maxLength) {
    if (input == null) {
      return "null";
    }
    int limit = Math.min(input.length(), maxLength);
    StringBuilder sb = new StringBuilder(limit + 64);
    for (int i = 0; i < limit; i++) {
      char c = input.charAt(i);
      if (c >= 32 && c < 127) {
        sb.append(c);
      } else {
        switch (c) {
          case '\n':
            sb.append("\\n");
            break;
          case '\r':
            sb.append("\\r");
            break;
          case '\t':
            sb.append("\\t");
            break;
          default:
            sb.append(String.format("\\u%04x", (int) c));
            break;
        }
      }
    }
    if (input.length() > maxLength) {
      sb.append("... [TRUNCATED]");
    }
    return sb.toString();
  }

  public CompletableFuture<Void> start() {
    return server
        .start()
        .thenRun(
            () -> {
              logger.atInfo().log("Server started, listening on %d.", port);
              healthManager.setStatus(ServingStatus.SERVING);
            });
  }

  public CompletableFuture<Void> stop() {
    healthManager.setStatus(ServingStatus.NOT_SERVING);
    return server.stop();
  }

  public int port() {
    return server.activeLocalPort();
  }

  public void blockUntilShutdown() throws InterruptedException {
    server.blockUntilShutdown();
  }

  public Server getServer() {
    return server;
  }

  public static class HealthManager {
    private final HealthStatusManager healthStatusManager;
    private final AtomicReference<ServingStatus> currentStatus;

    public HealthManager() {
      this.healthStatusManager = new HealthStatusManager();
      this.currentStatus = new AtomicReference<>(ServingStatus.UNKNOWN);
    }

    public synchronized void setStatus(ServingStatus status) {
      currentStatus.set(status);
      healthStatusManager.setStatus(HealthStatusManager.SERVICE_NAME_ALL_SERVICES, status);
    }

    public boolean isServing() {
      return currentStatus.get() == ServingStatus.SERVING;
    }

    public io.grpc.BindableService getGrpcHealthService() {
      return healthStatusManager.getHealthService();
    }
  }
}
