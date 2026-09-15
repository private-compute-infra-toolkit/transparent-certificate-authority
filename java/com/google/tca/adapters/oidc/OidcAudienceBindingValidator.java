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

import com.google.common.flogger.FluentLogger;
import com.google.common.io.BaseEncoding;
import com.google.tca.domain.AudienceBindingValidator;
import com.google.tca.domain.AudienceValidationException;
import com.google.tca.domain.CallerIdentity;
import com.google.tca.server.AwsInstanceMetadata;
import jakarta.inject.Inject;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** OIDC-specific implementation of audience binding validation. */
public final class OidcAudienceBindingValidator implements AudienceBindingValidator {
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();
  private static final Pattern AUDIENCE_PATTERN =
      Pattern.compile("^https://([^/]+)/v1/certificates:issue\\?pubkey_sha256=([a-f0-9]{64})$");

  private final AwsInstanceMetadata metadata;

  @Inject
  public OidcAudienceBindingValidator(AwsInstanceMetadata metadata) {
    this.metadata = metadata;
  }

  @Override
  public void validate(PublicKey csrPublicKey, CallerIdentity callerIdentity, String trustDomain) {
    logger.atInfo().log("OIDC Audience validation using trust domain: %s", trustDomain);

    String expectedDigest = getExpectedDigest(csrPublicKey);
    Set<String> audiences = callerIdentity.audiences();

    for (String audience : audiences) {
      Matcher matcher = AUDIENCE_PATTERN.matcher(audience);
      if (matcher.matches()) {
        String hostname = matcher.group(1);
        String digest = matcher.group(2);

        if (digest.equals(expectedDigest) && isValidHostname(hostname, trustDomain)) {
          return;
        }
      }
    }

    logger.atWarning().log(
        "OIDC audience binding mismatch. Valid audience must match format: "
            + "https://<hostname>/v1/certificates:issue?pubkey_sha256=%s, where <hostname> is "
            + "either a trust domain, global or regional hostname. Found audiences: %s",
        expectedDigest, audiences);
    throw new AudienceValidationException("OIDC audience binding validation failed.");
  }

  private boolean isValidHostname(String hostname, String trustDomain) {
    if (hostname.equals(trustDomain)) {
      return true;
    }

    String globalHostname = String.format("tca.%s.%s", metadata.environment(), metadata.domain());
    if (hostname.equals(globalHostname)) {
      return true;
    }

    String regionalHostname = String.format("%s.%s", metadata.region(), globalHostname);
    if (hostname.equals(regionalHostname)) {
      return true;
    }

    return false;
  }

  private static String getExpectedDigest(PublicKey csrPublicKey) {
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      byte[] hash = md.digest(csrPublicKey.getEncoded());
      return BaseEncoding.base16().lowerCase().encode(hash);
    } catch (NoSuchAlgorithmException e) {
      logger.atSevere().withCause(e).log("SHA-256 algorithm not found.");
      throw new IllegalStateException("SHA-256 algorithm not found.", e);
    }
  }
}
