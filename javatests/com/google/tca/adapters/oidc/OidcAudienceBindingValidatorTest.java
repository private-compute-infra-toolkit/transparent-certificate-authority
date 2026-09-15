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

package com.google.tca.adapters.oidc;

import static org.junit.Assert.assertThrows;

import com.google.common.io.BaseEncoding;
import com.google.tca.domain.AudienceValidationException;
import com.google.tca.domain.CallerIdentity;
import com.google.tca.server.AwsInstanceMetadata;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.util.Set;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public final class OidcAudienceBindingValidatorTest {
  private static final String TRUST_DOMAIN = "tca.pcit.local";
  private static final AwsInstanceMetadata METADATA =
      AwsInstanceMetadata.builder()
          .setRegion("us-east-1")
          .setAccountId("dummy_account")
          .setEnvironment("test")
          .setDomain("aws.pcit.local")
          .setInstanceId("i-testinstance")
          .build();

  private KeyPair keyPair;
  private OidcAudienceBindingValidator validator;

  @Before
  public void setUp() throws Exception {
    keyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
    validator = new OidcAudienceBindingValidator(METADATA);
  }

  @Test
  public void validate_trustDomainAudience_succeeds() throws Exception {
    String digest = computeDigest(keyPair.getPublic().getEncoded());
    String audience = "https://tca.pcit.local/v1/certificates:issue?pubkey_sha256=" + digest;
    CallerIdentity callerIdentity = new CallerIdentity("issuer", "subject", Set.of(audience));

    validator.validate(keyPair.getPublic(), callerIdentity, TRUST_DOMAIN);
  }

  @Test
  public void validate_globalHostnameAudience_succeeds() throws Exception {
    String digest = computeDigest(keyPair.getPublic().getEncoded());
    String audience =
        "https://tca.test.aws.pcit.local/v1/certificates:issue?pubkey_sha256=" + digest;
    CallerIdentity callerIdentity = new CallerIdentity("issuer", "subject", Set.of(audience));

    validator.validate(keyPair.getPublic(), callerIdentity, TRUST_DOMAIN);
  }

  @Test
  public void validate_regionalHostnameAudience_succeeds() throws Exception {
    String digest = computeDigest(keyPair.getPublic().getEncoded());
    String audience =
        "https://us-east-1.tca.test.aws.pcit.local/v1/certificates:issue?pubkey_sha256=" + digest;
    CallerIdentity callerIdentity = new CallerIdentity("issuer", "subject", Set.of(audience));

    validator.validate(keyPair.getPublic(), callerIdentity, TRUST_DOMAIN);
  }

  @Test
  public void validate_mismatchedRegionalAudience_fails() throws Exception {
    String digest = computeDigest(keyPair.getPublic().getEncoded());
    String audience =
        "https://us-west-1.tca.test.aws.pcit.local/v1/certificates:issue?pubkey_sha256=" + digest;
    CallerIdentity callerIdentity = new CallerIdentity("issuer", "subject", Set.of(audience));

    assertThrows(
        AudienceValidationException.class,
        () -> validator.validate(keyPair.getPublic(), callerIdentity, TRUST_DOMAIN));
  }

  @Test
  public void validate_globalHostnameAudienceWrongDomain_fails() throws Exception {
    String digest = computeDigest(keyPair.getPublic().getEncoded());
    String audience =
        "https://tca.test.aws.pcit.local1/v1/certificates:issue?pubkey_sha256=" + digest;
    CallerIdentity callerIdentity = new CallerIdentity("issuer", "subject", Set.of(audience));

    assertThrows(
        AudienceValidationException.class,
        () -> validator.validate(keyPair.getPublic(), callerIdentity, TRUST_DOMAIN));
  }

  @Test
  public void validate_globalHostnameAudienceWrongEnv_fails() throws Exception {
    String digest = computeDigest(keyPair.getPublic().getEncoded());
    String audience =
        "https://tca.test1.aws.pcit.local/v1/certificates:issue?pubkey_sha256=" + digest;
    CallerIdentity callerIdentity = new CallerIdentity("issuer", "subject", Set.of(audience));

    assertThrows(
        AudienceValidationException.class,
        () -> validator.validate(keyPair.getPublic(), callerIdentity, TRUST_DOMAIN));
  }

  @Test
  public void validate_regionalHostnameAudienceWrongDomain_fails() throws Exception {
    String digest = computeDigest(keyPair.getPublic().getEncoded());
    String audience =
        "https://us-east-1.tca.test.aws.pcit.local1/v1/certificates:issue?pubkey_sha256=" + digest;
    CallerIdentity callerIdentity = new CallerIdentity("issuer", "subject", Set.of(audience));

    assertThrows(
        AudienceValidationException.class,
        () -> validator.validate(keyPair.getPublic(), callerIdentity, TRUST_DOMAIN));
  }

  @Test
  public void validate_regionalHostnameAudienceWrongEnv_fails() throws Exception {
    String digest = computeDigest(keyPair.getPublic().getEncoded());
    String audience =
        "https://us-east-1.tca.test1.aws.pcit.local/v1/certificates:issue?pubkey_sha256=" + digest;
    CallerIdentity callerIdentity = new CallerIdentity("issuer", "subject", Set.of(audience));

    assertThrows(
        AudienceValidationException.class,
        () -> validator.validate(keyPair.getPublic(), callerIdentity, TRUST_DOMAIN));
  }

  @Test
  public void validate_trustDomainSubdomain_fails() throws Exception {
    String digest = computeDigest(keyPair.getPublic().getEncoded());
    String audience = "https://sub.tca.pcit.local/v1/certificates:issue?pubkey_sha256=" + digest;
    CallerIdentity callerIdentity = new CallerIdentity("issuer", "subject", Set.of(audience));

    assertThrows(
        AudienceValidationException.class,
        () -> validator.validate(keyPair.getPublic(), callerIdentity, TRUST_DOMAIN));
  }

  @Test
  public void validate_globalHostnameSubdomain_fails() throws Exception {
    String digest = computeDigest(keyPair.getPublic().getEncoded());
    String audience =
        "https://sub.tca.test.aws.pcit.local/v1/certificates:issue?pubkey_sha256=" + digest;
    CallerIdentity callerIdentity = new CallerIdentity("issuer", "subject", Set.of(audience));

    assertThrows(
        AudienceValidationException.class,
        () -> validator.validate(keyPair.getPublic(), callerIdentity, TRUST_DOMAIN));
  }

  @Test
  public void validate_regionalHostnameSubdomain_fails() throws Exception {
    String digest = computeDigest(keyPair.getPublic().getEncoded());
    String audience =
        "https://sub.us-east-1.tca.test.aws.pcit.local/v1/certificates:issue?pubkey_sha256="
            + digest;
    CallerIdentity callerIdentity = new CallerIdentity("issuer", "subject", Set.of(audience));

    assertThrows(
        AudienceValidationException.class,
        () -> validator.validate(keyPair.getPublic(), callerIdentity, TRUST_DOMAIN));
  }

  @Test
  public void validate_trustDomainTopLevel_fails() throws Exception {
    String digest = computeDigest(keyPair.getPublic().getEncoded());
    String audience = "https://tca.pcit.local.top/v1/certificates:issue?pubkey_sha256=" + digest;
    CallerIdentity callerIdentity = new CallerIdentity("issuer", "subject", Set.of(audience));

    assertThrows(
        AudienceValidationException.class,
        () -> validator.validate(keyPair.getPublic(), callerIdentity, TRUST_DOMAIN));
  }

  @Test
  public void validate_globalHostnameTopLevel_fails() throws Exception {
    String digest = computeDigest(keyPair.getPublic().getEncoded());
    String audience =
        "https://tca.test.aws.pcit.local.top/v1/certificates:issue?pubkey_sha256=" + digest;
    CallerIdentity callerIdentity = new CallerIdentity("issuer", "subject", Set.of(audience));

    assertThrows(
        AudienceValidationException.class,
        () -> validator.validate(keyPair.getPublic(), callerIdentity, TRUST_DOMAIN));
  }

  @Test
  public void validate_regionalHostnameTopLevel_fails() throws Exception {
    String digest = computeDigest(keyPair.getPublic().getEncoded());
    String audience =
        "https://us-east-1.tca.test.aws.pcit.local.top/v1/certificates:issue?pubkey_sha256="
            + digest;
    CallerIdentity callerIdentity = new CallerIdentity("issuer", "subject", Set.of(audience));

    assertThrows(
        AudienceValidationException.class,
        () -> validator.validate(keyPair.getPublic(), callerIdentity, TRUST_DOMAIN));
  }

  @Test
  public void validate_mismatchedBinding_fails() throws Exception {
    String audience = "https://tca.pcit.local/v1/certificates:issue?pubkey_sha256=wrong-digest";
    CallerIdentity callerIdentity = new CallerIdentity("issuer", "subject", Set.of(audience));

    assertThrows(
        AudienceValidationException.class,
        () -> validator.validate(keyPair.getPublic(), callerIdentity, TRUST_DOMAIN));
  }

  @Test
  public void validate_missingBinding_fails() throws Exception {
    CallerIdentity callerIdentity =
        new CallerIdentity("issuer", "subject", Set.of("other-audience"));

    assertThrows(
        AudienceValidationException.class,
        () -> validator.validate(keyPair.getPublic(), callerIdentity, TRUST_DOMAIN));
  }

  @Test
  public void validate_multipleAudiences_oneValid_succeeds() throws Exception {
    String digest = computeDigest(keyPair.getPublic().getEncoded());
    String validAudience = "https://tca.pcit.local/v1/certificates:issue?pubkey_sha256=" + digest;
    String invalidAudience =
        "https://tca.pcit.local/v1/certificates:issue?pubkey_sha256=wrong-digest";
    CallerIdentity callerIdentity =
        new CallerIdentity("issuer", "subject", Set.of(invalidAudience, validAudience));

    validator.validate(keyPair.getPublic(), callerIdentity, TRUST_DOMAIN);
  }

  private String computeDigest(byte[] data) throws Exception {
    MessageDigest md = MessageDigest.getInstance("SHA-256");
    byte[] hash = md.digest(data);
    return BaseEncoding.base16().lowerCase().encode(hash);
  }
}
