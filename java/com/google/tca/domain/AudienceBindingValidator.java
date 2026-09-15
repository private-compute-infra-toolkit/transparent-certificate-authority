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

package com.google.tca.domain;

import java.security.PublicKey;

/** Interface for audience binding validation logic. */
public interface AudienceBindingValidator {
  /**
   * Validates that the public key is correctly bound to the caller's identity and trust domain.
   *
   * @param csrPublicKey the public key from the CSR.
   * @param callerIdentity the identity of the caller.
   * @param trustDomain the active trust domain extracted from the root certificate.
   * @throws AudienceValidationException if validation fails.
   */
  void validate(PublicKey csrPublicKey, CallerIdentity callerIdentity, String trustDomain);
}
