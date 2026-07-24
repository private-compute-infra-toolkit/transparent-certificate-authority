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

package com.google.tca.domain.metric;

import java.time.Duration;

public interface Metrics {
  /** Tracks the success or failure of JWT token authentication. */
  void incrementAuthenticationCounter(Status status);

  void incrementProcessingCounter(ProcessingStatus status);

  void allowMetricsForClientId(String clientId);

  void incrementCertificateIssuanceCounter(String clientId);

  void setRootCertificateValidity(Duration remaining);

  /** Records that a JWKS key lookup was performed. */
  void recordOidcJwksLookup();

  /** Records that a JWKS cache miss (fetch) occurred. */
  void recordOidcJwksMiss();

  /** Records the duration of an OIDC JWKS key fetch call. */
  void recordOidcJwksFetchTime(Duration duration);

  /** Records the duration of a sub-operation within the certificate issuance call. */
  void recordIssuanceSubOperationTime(IssuanceSubOperation operation, Duration duration);

  interface IssuanceTimer {
    void recordSubOperationAndResetTimer(IssuanceSubOperation operation);
  }

  IssuanceTimer startIssuanceTimer();
}
