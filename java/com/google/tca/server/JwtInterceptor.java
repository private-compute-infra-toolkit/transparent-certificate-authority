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

import static com.google.tca.domain.metric.Status.FAILURE;
import static com.google.tca.domain.metric.Status.SUCCESS;

import com.google.common.flogger.FluentLogger;
import com.google.tca.domain.metric.Metrics;
import io.grpc.Context;
import io.grpc.Contexts;
import io.grpc.Metadata;
import io.grpc.ServerCall;
import io.grpc.ServerCallHandler;
import io.grpc.ServerInterceptor;
import io.grpc.Status;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.Locator;
import jakarta.inject.Inject;
import java.security.Key;
import java.time.Duration;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/** Interceptor that extracts the issuer from a JWT token in the Authorization header. */
public final class JwtInterceptor implements ServerInterceptor {
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();

  public static final Metadata.Key<String> AUTHORIZATION_METADATA_KEY =
      Metadata.Key.of("Authorization", Metadata.ASCII_STRING_MARSHALLER);

  public static final Context.Key<String> ISSUER_CONTEXT_KEY = Context.key("issuer");
  public static final Context.Key<String> SUBJECT_CONTEXT_KEY = Context.key("subject");
  public static final Context.Key<Set<String>> AUDIENCE_CONTEXT_KEY = Context.key("audience");

  private final Locator<Key> keyLocator;
  private final Metrics metrics;

  @Inject
  public JwtInterceptor(@JwtAuth Locator<Key> keyLocator, Metrics metrics) {
    this.keyLocator = keyLocator;
    this.metrics = metrics;
  }

  @Override
  public <ReqT, RespT> ServerCall.Listener<ReqT> interceptCall(
      ServerCall<ReqT, RespT> call, Metadata headers, ServerCallHandler<ReqT, RespT> next) {
    long startNano = System.nanoTime();
    String authHeader = headers.get(AUTHORIZATION_METADATA_KEY);

    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      logger.atWarning().log("Missing or invalid Authorization header");
      call.close(
          Status.UNAUTHENTICATED.withDescription("Missing or invalid Authorization header"),
          new Metadata());
      metrics.incrementAuthenticationCounter(FAILURE);
      metrics.recordOidcAuthenticationTime(Duration.ofNanos(System.nanoTime() - startNano));
      return new ServerCall.Listener<ReqT>() {};
    }

    String token = authHeader.substring("Bearer ".length());

    try {
      Claims claims = Jwts.parser().keyLocator(keyLocator).build().parseClaimsJws(token).getBody();

      String issuer = claims.getIssuer();
      String subject = claims.getSubject();
      Set<String> audiences = extractAudiences(claims.getAudience());
      logger.atInfo().log(
          "Extracted issuer from JWT: %s, subject: %s, audiences: %s", issuer, subject, audiences);

      Context context =
          Context.current()
              .withValue(ISSUER_CONTEXT_KEY, issuer)
              .withValue(SUBJECT_CONTEXT_KEY, subject)
              .withValue(AUDIENCE_CONTEXT_KEY, audiences);
      metrics.incrementAuthenticationCounter(SUCCESS);
      metrics.recordOidcAuthenticationTime(Duration.ofNanos(System.nanoTime() - startNano));
      return Contexts.interceptCall(context, call, headers, next);
    } catch (JwtException e) {
      logger.atWarning().withCause(e).log("Failed to parse JWT token");
      call.close(
          Status.UNAUTHENTICATED.withDescription("Failed to parse JWT token"), new Metadata());
      metrics.incrementAuthenticationCounter(FAILURE);
      metrics.recordOidcAuthenticationTime(Duration.ofNanos(System.nanoTime() - startNano));
      return new ServerCall.Listener<ReqT>() {};
    }
  }

  private Set<String> extractAudiences(Object aud) {
    if (aud == null) {
      return Collections.emptySet();
    }
    if (aud instanceof String) {
      return Collections.singleton((String) aud);
    }
    if (aud instanceof Collection) {
      Set<String> audiences = new HashSet<>();
      for (Object item : (Collection<?>) aud) {
        if (item instanceof String) {
          audiences.add((String) item);
        }
      }
      return Collections.unmodifiableSet(audiences);
    }
    return Collections.emptySet();
  }
}
