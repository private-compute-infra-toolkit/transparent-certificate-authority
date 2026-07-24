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

package com.google.tca.adapters.oidc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.google.common.collect.ImmutableMap;
import com.google.common.flogger.FluentLogger;
import com.google.tca.domain.metric.Metrics;
import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.time.InstantSource;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Fetches and caches JWKS keys from an OIDC endpoint. */
public class OidcJwksKeyFetcher {
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();
  private final HttpClient httpClient;
  private final ObjectMapper objectMapper;
  private static final Pattern MAX_AGE_PATTERN = Pattern.compile("max-age\\s*=\\s*(\\d+)");
  private static final long DEFAULT_CACHE_DURATION_SECS = TimeUnit.HOURS.toSeconds(1);
  private static final String CACHE_KEY = "jwks";
  private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(5);
  private static final String RSA_ALGORITHM = "RSA";
  private static final Duration MIN_REFRESH_INTERVAL = Duration.ofMinutes(1);

  private record JwksData(Map<String, Key> keys, long maxAgeSecs, java.time.Instant fetchedAt) {}

  private record Jwk(String kid, String kty, String n, String e) {}

  private record JwksResponse(List<Jwk> keys) {}

  private final JwksUriProvider jwksUriProvider;
  private final InstantSource instantSource;
  private final Metrics metrics;
  private final LoadingCache<String, JwksData> cache;

  /**
   * Constructs a new OidcJwksKeyFetcher instance.
   *
   * @param jwksUriProvider the provider for the JWKS URI.
   * @param instantSource the source for the current time, used for cache expiration.
   * @param httpClient the HTTP client to use for fetching the JWKS.
   * @param objectMapper the object mapper to parse JSON.
   */
  public OidcJwksKeyFetcher(
      JwksUriProvider jwksUriProvider,
      InstantSource instantSource,
      HttpClient httpClient,
      ObjectMapper objectMapper,
      Metrics metrics) {
    this.jwksUriProvider = jwksUriProvider;
    this.instantSource = instantSource;
    this.httpClient = httpClient;
    this.objectMapper = objectMapper;
    this.metrics = metrics;
    this.cache =
        Caffeine.newBuilder()
            .ticker(() -> TimeUnit.MILLISECONDS.toNanos(instantSource.millis()))
            .expireAfter(new JwksExpiry())
            .build(unused -> fetchJwks());
  }

  /**
   * Returns the public key for the given key ID.
   *
   * @param keyId the ID of the key to retrieve.
   * @return an {@link Optional} containing the public key, or an empty {@link Optional} if the key
   *     is not found.
   */
  public Optional<Key> getKey(String keyId) {
    metrics.recordOidcJwksLookup();
    JwksData data = cache.get(CACHE_KEY);
    Key key = data.keys.get(keyId);
    if (key != null) {
      return Optional.of(key);
    }

    // Key not found in cache. If the cache is older than the minimum refresh interval,
    // invalidate and re-fetch to handle potential key rotation before natural expiry.
    if (shouldAttemptRefresh(data)) {
      logger.atInfo().log(
          "Key %s not found in cache and cache is older than %s. Refreshing JWKS.",
          keyId, MIN_REFRESH_INTERVAL);
      cache.invalidate(CACHE_KEY);
      data = cache.get(CACHE_KEY);
      return Optional.ofNullable(data.keys().get(keyId));
    }
    return Optional.empty();
  }

  private boolean shouldAttemptRefresh(JwksData data) {
    Instant now = Instant.ofEpochMilli(instantSource.millis());
    return now.isAfter(data.fetchedAt().plus(MIN_REFRESH_INTERVAL));
  }

  private JwksData fetchJwks() {
    metrics.recordOidcJwksMiss();
    long startTimeNanos = System.nanoTime();
    try {
      String jwksUri = jwksUriProvider.getJwksUri();
      HttpRequest request =
          HttpRequest.newBuilder().uri(URI.create(jwksUri)).timeout(HTTP_TIMEOUT).build();
      HttpResponse<String> response =
          httpClient.send(request, HttpResponse.BodyHandlers.ofString());

      if (response.statusCode() != 200) {
        throw new IOException("Failed to fetch JWKS: " + response.body());
      }

      long maxAgeSecs = getMaxAgeSecs(response.headers().firstValue("Cache-Control"));
      JwksResponse jwksResponse = objectMapper.readValue(response.body(), JwksResponse.class);

      return new JwksData(
          parseKeys(jwksResponse), maxAgeSecs, Instant.ofEpochMilli(instantSource.millis()));
    } catch (IOException | InterruptedException e) {
      throw new RuntimeException("Failed to fetch or parse JWKS", e);
    } finally {
      metrics.recordOidcJwksFetchTime(Duration.ofNanos(System.nanoTime() - startTimeNanos));
    }
  }

  private Map<String, Key> parseKeys(JwksResponse jwksResponse) {
    if (jwksResponse == null || jwksResponse.keys() == null) {
      return ImmutableMap.of();
    }

    Map<String, Key> keys = new java.util.HashMap<>();
    for (Jwk jwk : jwksResponse.keys()) {
      if (jwk.kid() == null) {
        continue;
      }
      parseKey(jwk).ifPresent(key -> keys.put(jwk.kid(), key));
    }
    return ImmutableMap.copyOf(keys);
  }

  private Optional<Key> parseKey(Jwk jwk) {
    // TODO: Add support for EC keys (e.g., P-256) once required.
    // For now, only RSA keys are supported.
    if (!RSA_ALGORITHM.equals(jwk.kty())) {
      return Optional.empty();
    }
    if (jwk.n() == null || jwk.e() == null) {
      logger.atWarning().log("JWK with kid %s is missing %s parameters.", jwk.kid(), RSA_ALGORITHM);
      return Optional.empty();
    }

    try {
      BigInteger modulus = new BigInteger(1, Base64.getUrlDecoder().decode(jwk.n()));
      BigInteger exponent = new BigInteger(1, Base64.getUrlDecoder().decode(jwk.e()));

      RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
      KeyFactory factory = KeyFactory.getInstance(RSA_ALGORITHM);
      return Optional.of(factory.generatePublic(spec));
    } catch (NoSuchAlgorithmException | InvalidKeySpecException | IllegalArgumentException e) {
      logger.atWarning().withCause(e).log(
          "Failed to parse %s JWK with kid: %s.", RSA_ALGORITHM, jwk.kid());
      return Optional.empty();
    }
  }

  private long getMaxAgeSecs(Optional<String> cacheControlHeader) {
    return cacheControlHeader
        .map(MAX_AGE_PATTERN::matcher)
        .filter(Matcher::find)
        .map(m -> Long.parseLong(m.group(1)))
        .filter(age -> age >= 0)
        .orElse(DEFAULT_CACHE_DURATION_SECS);
  }

  /** Custom expiry logic for the JWKS cache based on the 'max-age' from 'Cache-Control' header. */
  private static final class JwksExpiry implements Expiry<String, JwksData> {
    @Override
    public long expireAfterCreate(String key, JwksData value, long currentTime) {
      return TimeUnit.SECONDS.toNanos(value.maxAgeSecs);
    }

    @Override
    public long expireAfterUpdate(
        String key, JwksData value, long currentTime, long currentDuration) {
      return currentDuration;
    }

    @Override
    public long expireAfterRead(
        String key, JwksData value, long currentTime, long currentDuration) {
      return currentDuration;
    }
  }
}
