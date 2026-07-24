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

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.tca.domain.metric.Metrics;
import java.io.IOException;
import java.net.http.HttpClient;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.InstantSource;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

@RunWith(JUnit4.class)
public class OidcJwksKeyFetcherTest {
  private static final String TEST_KEY_ID = "test-key-id";

  @Rule public final MockitoRule mockito = MockitoJUnit.rule();

  private MockWebServer server;
  private String testJwkSet;
  private OidcJwksKeyFetcher keyFetcher;

  @Mock private InstantSource mockInstantSource;
  @Mock private Metrics mockMetrics;

  @Before
  public void setUp() throws Exception {
    server = new MockWebServer();
    server.start();
    com.fasterxml.jackson.databind.ObjectMapper mapper =
        new com.fasterxml.jackson.databind.ObjectMapper()
            .disable(
                com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
    keyFetcher =
        new OidcJwksKeyFetcher(
            () -> server.url("/").toString(),
            mockInstantSource,
            HttpClient.newHttpClient(),
            mapper,
            mockMetrics);

    // Generate a real RSA key pair to create a valid JWKS.
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(2048);
    KeyPair keyPair = keyGen.generateKeyPair();
    RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();

    String n = Base64.getUrlEncoder().encodeToString(rsaPublicKey.getModulus().toByteArray());
    String e =
        Base64.getUrlEncoder().encodeToString(rsaPublicKey.getPublicExponent().toByteArray());

    testJwkSet =
        String.format(
            "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"%s\",\"n\":\"%s\",\"e\":\"%s\"}]}",
            TEST_KEY_ID, n, e);
  }

  @After
  public void tearDown() throws IOException {
    server.shutdown();
  }

  @Test
  public void getKey_firstCall_fetchesKey() {
    server.enqueue(new MockResponse().setBody(testJwkSet));
    when(mockInstantSource.millis()).thenReturn(Instant.now().toEpochMilli());

    Optional<Key> key = keyFetcher.getKey(TEST_KEY_ID);

    assertThat(key).isPresent();
    assertThat(server.getRequestCount()).isEqualTo(1);
    verify(mockMetrics).recordOidcJwksLookup();
    verify(mockMetrics).recordOidcJwksMiss();
    verify(mockMetrics).recordOidcJwksFetchTime(any());
  }

  @Test
  public void getKey_cachedKey_returnsKeyWithoutFetch() {
    server.enqueue(new MockResponse().setBody(testJwkSet));
    when(mockInstantSource.millis()).thenReturn(Instant.now().toEpochMilli());

    keyFetcher.getKey(TEST_KEY_ID); // First call to cache the key.

    // Second call should hit the cache.
    Optional<Key> key = keyFetcher.getKey(TEST_KEY_ID);

    assertThat(key).isPresent();
    assertThat(server.getRequestCount()).isEqualTo(1);
    verify(mockMetrics, times(2)).recordOidcJwksLookup();
    verify(mockMetrics, times(1)).recordOidcJwksMiss();
    verify(mockMetrics, times(1)).recordOidcJwksFetchTime(any());
  }

  @Test
  public void getKey_expiredCache_fetchesKeyAgain() {
    server.enqueue(new MockResponse().setHeader("Cache-Control", "max-age=60").setBody(testJwkSet));
    Instant now = Instant.now();
    when(mockInstantSource.millis()).thenReturn(now.toEpochMilli());

    keyFetcher.getKey(TEST_KEY_ID); // First call.

    // Advance the clock past the cache expiry.
    when(mockInstantSource.millis()).thenReturn(now.plusSeconds(61).toEpochMilli());

    server.enqueue(new MockResponse().setBody(testJwkSet)); // For the second fetch.
    keyFetcher.getKey(TEST_KEY_ID);

    // Two requests should have been made.
    assertThat(server.getRequestCount()).isEqualTo(2);
  }

  @Test
  public void getKey_noCacheControl_usesDefaultExpiration() {
    server.enqueue(new MockResponse().setBody(testJwkSet));
    Instant now = Instant.now();
    when(mockInstantSource.millis()).thenReturn(now.toEpochMilli());

    keyFetcher.getKey(TEST_KEY_ID);

    // Advance clock by less than the default (1 hour).
    when(mockInstantSource.millis()).thenReturn(now.plusSeconds(1800).toEpochMilli());
    keyFetcher.getKey(TEST_KEY_ID);

    // Should still be cached.
    assertThat(server.getRequestCount()).isEqualTo(1);

    // Advance clock past the default expiration.
    when(mockInstantSource.millis()).thenReturn(now.plusSeconds(3601).toEpochMilli());
    server.enqueue(new MockResponse().setBody(testJwkSet));
    keyFetcher.getKey(TEST_KEY_ID);

    assertThat(server.getRequestCount()).isEqualTo(2);
  }

  @Test
  public void getKey_serverError_throwsException() {
    server.enqueue(new MockResponse().setResponseCode(500));
    when(mockInstantSource.millis()).thenReturn(Instant.now().toEpochMilli());

    assertThrows(RuntimeException.class, () -> keyFetcher.getKey(TEST_KEY_ID));
  }

  @Test
  public void getKey_keyNotFound_returnsEmpty() {
    server.enqueue(new MockResponse().setBody(testJwkSet));
    when(mockInstantSource.millis()).thenReturn(Instant.now().toEpochMilli());

    Optional<Key> key = keyFetcher.getKey("non-existent-key");

    assertThat(key).isEmpty();
  }

  @Test
  public void getKey_maxAgeZero_usesZeroExpiration() {
    server.enqueue(new MockResponse().setHeader("Cache-Control", "max-age=0").setBody(testJwkSet));
    Instant now = Instant.now();
    when(mockInstantSource.millis()).thenReturn(now.toEpochMilli());

    keyFetcher.getKey(TEST_KEY_ID); // First call.

    // Advance the clock by 1 second.
    when(mockInstantSource.millis()).thenReturn(now.plusSeconds(1).toEpochMilli());

    server.enqueue(new MockResponse().setBody(testJwkSet)); // For the second fetch.
    keyFetcher.getKey(TEST_KEY_ID);

    // Should have been two requests because max-age=0 is now respected.
    assertThat(server.getRequestCount()).isEqualTo(2);
  }

  @Test
  public void getKey_cacheControl_honorsMaxAgeWithAndWithoutSpaces() {
    // Test both 'max-age=60' and 'max-age = 60' (RFC 7234 allows optional spaces).
    String[] headerValues = {"max-age=60", "max-age = 60"};
    int expectedRequests = 0;
    Instant now = Instant.now();

    for (String headerValue : headerValues) {
      server.enqueue(
          new MockResponse().setHeader("Cache-Control", headerValue).setBody(testJwkSet));
      when(mockInstantSource.millis()).thenReturn(now.toEpochMilli());

      keyFetcher.getKey(TEST_KEY_ID); // Initial fetch or refresh.
      expectedRequests++;

      // Advance clock past 60s to trigger expiry.
      now = now.plusSeconds(61);
      when(mockInstantSource.millis()).thenReturn(now.toEpochMilli());
      server.enqueue(new MockResponse().setBody(testJwkSet));

      keyFetcher.getKey(TEST_KEY_ID); // Should fetch again.
      expectedRequests++;

      assertThat(server.getRequestCount()).isEqualTo(expectedRequests);

      // Advance clock further to ensure next iteration starts with an expired cache.
      now = now.plusSeconds(3601);
    }
  }

  @Test
  public void getKey_duplicateKid_succeeds() {
    KeyPairGenerator keyGen;
    try {
      keyGen = KeyPairGenerator.getInstance("RSA");
    } catch (Exception e) {
      throw new RuntimeException(e);
    }
    keyGen.initialize(2048);
    KeyPair keyPair = keyGen.generateKeyPair();
    RSAPublicKey rsaPublicKey = (RSAPublicKey) keyPair.getPublic();

    String n = Base64.getUrlEncoder().encodeToString(rsaPublicKey.getModulus().toByteArray());
    String e =
        Base64.getUrlEncoder().encodeToString(rsaPublicKey.getPublicExponent().toByteArray());

    String duplicateJwkSet =
        String.format(
            "{\"keys\":["
                + "{\"kty\":\"RSA\",\"kid\":\"dup\",\"n\":\"%s\",\"e\":\"%s\"},"
                + "{\"kty\":\"RSA\",\"kid\":\"dup\",\"n\":\"%s\",\"e\":\"%s\"}"
                + "]}",
            n, e, n, e);

    server.enqueue(new MockResponse().setBody(duplicateJwkSet));
    when(mockInstantSource.millis()).thenReturn(Instant.now().toEpochMilli());

    // Should no longer throw RuntimeException.
    Optional<Key> key = keyFetcher.getKey("dup");
    assertThat(key).isPresent();
  }

  @Test
  public void getKey_timeout_throwsException() {
    server.enqueue(
        new MockResponse()
            .setBody(testJwkSet)
            .setHeadersDelay(6, TimeUnit.SECONDS)); // Longer than 10s timeout
    when(mockInstantSource.millis()).thenReturn(Instant.now().toEpochMilli());

    assertThrows(RuntimeException.class, () -> keyFetcher.getKey(TEST_KEY_ID));
  }

  @Test
  public void getKey_keyRotation_triggersReactiveRefresh() {
    server.enqueue(new MockResponse().setBody(testJwkSet));
    Instant now = Instant.now();
    when(mockInstantSource.millis()).thenReturn(now.toEpochMilli());

    keyFetcher.getKey(TEST_KEY_ID); // Initial fetch.
    assertThat(server.getRequestCount()).isEqualTo(1);

    // Advance clock past the minimum refresh interval (1 minute).
    now = now.plusSeconds(61);
    when(mockInstantSource.millis()).thenReturn(now.toEpochMilli());

    // Enqueue a new JWKS that contains a new key.
    String newKeyId = "new-key-id";
    String newJwkSet = testJwkSet.replace(TEST_KEY_ID, newKeyId);
    server.enqueue(new MockResponse().setBody(newJwkSet));

    // Requesting the new key should trigger a refresh because it's missing and interval passed.
    Optional<Key> key = keyFetcher.getKey(newKeyId);

    assertThat(key).isPresent();
    assertThat(server.getRequestCount()).isEqualTo(2);
  }

  @Test
  public void getKey_keyNotFound_recentFetch_returnsEmptyWithoutRefresh() {
    server.enqueue(new MockResponse().setBody(testJwkSet));
    Instant now = Instant.now();
    when(mockInstantSource.millis()).thenReturn(now.toEpochMilli());

    keyFetcher.getKey(TEST_KEY_ID); // Initial fetch.
    assertThat(server.getRequestCount()).isEqualTo(1);

    // Advance clock by only 30 seconds (less than 1 minute).
    now = now.plusSeconds(30);
    when(mockInstantSource.millis()).thenReturn(now.toEpochMilli());

    // Requesting a non-existent key should NOT trigger a refresh.
    Optional<Key> key = keyFetcher.getKey("missing-key");

    assertThat(key).isEmpty();
    assertThat(server.getRequestCount()).isEqualTo(1);
  }

  @Test
  public void getKey_withExtraFields_succeeds() {
    String testJwkSetWithExtraFields =
        testJwkSet.replace("}]}", ",\"use\":\"sig\",\"alg\":\"RS256\"}]}");
    server.enqueue(new MockResponse().setBody(testJwkSetWithExtraFields));
    when(mockInstantSource.millis()).thenReturn(Instant.now().toEpochMilli());

    Optional<Key> key = keyFetcher.getKey(TEST_KEY_ID);

    assertThat(key).isPresent();
  }
}
