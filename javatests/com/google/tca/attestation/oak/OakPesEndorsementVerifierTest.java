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

package com.google.tca.attestation.oak;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.oak.Variant;
import com.google.oak.attestation.v1.AttestationResults;
import com.google.oak.attestation.v1.ContainerEndorsement;
import com.google.oak.attestation.v1.Endorsements;
import com.google.oak.attestation.v1.ReferenceValues;
import com.google.oak.attestation.v1.VerifyingKey;
import com.google.oak.attestation.v1.VerifyingKeySet;
import com.google.protobuf.ByteString;
import com.google.protobuf.TextFormat;
import com.google.tca.adapters.OakAttestationEvidence;
import com.google.tca.attestation.oak.OakAttestationVerifier.AttestationVerificationException;
import com.google.tca.v1.IssueCertificateRequest;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.stream.IntStream;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class OakPesEndorsementVerifierTest {
  private static final String GOLDEN_REQUEST_PATH =
      "javatests/com/google/tca/server/testdata/golden_request.textproto";
  private static final String PES_ENDORSEMENT_REFERENCE_VALUES_PATH =
      "javatests/com/google/tca/attestation/oak/testdata/pes_endorsement_reference_values.textproto";

  // Within the endorsement validity period (2026-06-25T14:52:25.941Z)
  private static final long VALID_TEST_TIMESTAMP_MILLIS =
      Instant.parse("2026-06-25T14:52:25.941000Z").toEpochMilli();

  private static OakEvidenceVerifier verifier;
  private static byte[] evidence;
  private static byte[] endorsements;
  private static Endorsements parsedEndorsements;
  private static int containerEventIndex;
  private static ContainerEndorsement containerEndorsement;
  private static JsonObject pesConfirmationJson;
  private static ReferenceValues baseReferenceValues;
  private static VerifyingKey dummyKey1;
  private static VerifyingKey matchingPesKey;
  private static VerifyingKey dummyKey2;
  private static JsonObject validPesSignatureJson;
  private static JsonObject untrustedKeyPesSignatureJson;
  private static JsonObject corruptedPesSignatureJson;

  @BeforeClass
  public static void setUpClass() throws Exception {
    verifier = new OakEvidenceVerifier();

    String goldenRequestText = Files.readString(Paths.get(GOLDEN_REQUEST_PATH));
    IssueCertificateRequest.Builder requestBuilder = IssueCertificateRequest.newBuilder();
    TextFormat.Parser parser = TextFormat.Parser.newBuilder().setAllowUnknownFields(true).build();
    parser.merge(goldenRequestText, requestBuilder);
    IssueCertificateRequest request = requestBuilder.build();

    evidence =
        request.getAttestationEvidence().getOakAttestationEvidence().getEvidence().toByteArray();
    parsedEndorsements =
        request.getAttestationEvidence().getOakAttestationEvidence().getEndorsements();
    endorsements = parsedEndorsements.toByteArray();

    containerEventIndex = findContainerEventIndex(parsedEndorsements);
    containerEndorsement =
        ContainerEndorsement.parseFrom(
            parsedEndorsements.getEvents(containerEventIndex).getValue());
    pesConfirmationJson =
        JsonParser.parseString(containerEndorsement.getBinary().getPesConfirmation().toStringUtf8())
            .getAsJsonObject();
    validPesSignatureJson =
        pesConfirmationJson
            .getAsJsonArray("endorsementSignatures")
            .get(0)
            .getAsJsonObject()
            .deepCopy();
    // statementSignature shares the google.pes.v1.Signature JSON schema with endorsementSignatures,
    // while its endorser public key is not present in the PES trusted key_set.
    untrustedKeyPesSignatureJson =
        pesConfirmationJson.getAsJsonObject("statementSignature").deepCopy();
    corruptedPesSignatureJson = validPesSignatureJson.deepCopy();
    corruptedPesSignatureJson.addProperty(
        "signature", Base64.getEncoder().encodeToString(new byte[256]));

    String refValuesText = Files.readString(Paths.get(PES_ENDORSEMENT_REFERENCE_VALUES_PATH));
    ReferenceValues.Builder refValuesBuilder = ReferenceValues.newBuilder();
    parser.merge(refValuesText, refValuesBuilder);
    baseReferenceValues = refValuesBuilder.build();

    List<VerifyingKey> keys =
        baseReferenceValues
            .getOakContainers()
            .getContainerLayer()
            .getBinary()
            .getPesEndorsement()
            .getKeySet()
            .getKeysList();
    dummyKey1 = keys.get(0);
    matchingPesKey = keys.get(1);
    dummyKey2 = keys.get(2);
  }

  private static int findContainerEventIndex(Endorsements parsedEndorsements) {
    return IntStream.range(0, parsedEndorsements.getEventsCount())
        .filter(
            i ->
                parsedEndorsements
                    .getEvents(i)
                    .getId()
                    .equals(OakAttestationEvidence.CONTAINER_ENDORSEMENT_ID))
        .findFirst()
        .orElseThrow(
            () ->
                new IllegalStateException(
                    "Container endorsement event not found in golden_request.textproto"));
  }

  private static ReferenceValues withPesKeys(List<VerifyingKey> pesKeys) {
    ReferenceValues.Builder builder = baseReferenceValues.toBuilder();
    builder
        .getOakContainersBuilder()
        .getContainerLayerBuilder()
        .getBinaryBuilder()
        .getPesEndorsementBuilder()
        .setKeySet(VerifyingKeySet.newBuilder().addAllKeys(pesKeys));
    return builder.build();
  }

  private static ReferenceValues withPublisherId(String publisherId) {
    ReferenceValues.Builder builder = baseReferenceValues.toBuilder();
    builder
        .getOakContainersBuilder()
        .getContainerLayerBuilder()
        .getBinaryBuilder()
        .getPesEndorsementBuilder()
        .setPublisherId(publisherId);
    return builder.build();
  }

  private static byte[] withEndorsementSignatures(List<JsonObject> signatures) {
    Endorsements.Builder endorsementsBuilder = parsedEndorsements.toBuilder();
    Variant containerEvent = endorsementsBuilder.getEvents(containerEventIndex);
    ContainerEndorsement.Builder containerEndorsementBuilder = containerEndorsement.toBuilder();

    JsonObject updatedPesConfirmationJson = pesConfirmationJson.deepCopy();
    JsonArray sigArray = new JsonArray();
    for (JsonObject sig : signatures) {
      sigArray.add(sig);
    }
    updatedPesConfirmationJson.add("endorsementSignatures", sigArray);

    containerEndorsementBuilder
        .getBinaryBuilder()
        .setPesConfirmation(ByteString.copyFromUtf8(updatedPesConfirmationJson.toString()));
    endorsementsBuilder.setEvents(
        containerEventIndex,
        containerEvent.toBuilder()
            .setValue(containerEndorsementBuilder.build().toByteString())
            .build());
    return endorsementsBuilder.build().toByteArray();
  }

  @Test
  public void testOakVerifier_pesEndorsement_multipleKeysInKeySet_firstKeyMismatch_succeeds()
      throws Exception {
    AttestationResults results =
        verifier.verify(
            VALID_TEST_TIMESTAMP_MILLIS, evidence, endorsements, baseReferenceValues.toByteArray());

    assertThat(results.getStatus()).isEqualTo(AttestationResults.Status.STATUS_SUCCESS);
  }

  @Test
  public void testOakVerifier_pesEndorsement_matchingKeyAtTailOfKeySet_succeeds() throws Exception {
    ReferenceValues refValues = withPesKeys(List.of(dummyKey1, dummyKey2, matchingPesKey));

    AttestationResults results =
        verifier.verify(
            VALID_TEST_TIMESTAMP_MILLIS, evidence, endorsements, refValues.toByteArray());

    assertThat(results.getStatus()).isEqualTo(AttestationResults.Status.STATUS_SUCCESS);
  }

  @Test
  public void testOakVerifier_pesEndorsement_singleMatchingKey_succeeds() throws Exception {
    ReferenceValues refValues = withPesKeys(List.of(matchingPesKey));

    AttestationResults results =
        verifier.verify(
            VALID_TEST_TIMESTAMP_MILLIS, evidence, endorsements, refValues.toByteArray());

    assertThat(results.getStatus()).isEqualTo(AttestationResults.Status.STATUS_SUCCESS);
  }

  @Test
  public void testOakVerifier_pesEndorsement_keyNotInKeySet_fails() {
    ReferenceValues refValues = withPesKeys(List.of(dummyKey1, dummyKey2));

    AttestationVerificationException exception =
        assertThrows(
            AttestationVerificationException.class,
            () ->
                verifier.verify(
                    VALID_TEST_TIMESTAMP_MILLIS, evidence, endorsements, refValues.toByteArray()));

    assertThat(exception.getMessage()).contains("PES public key not found in trusted key set");
  }

  @Test
  public void testOakVerifier_pesEndorsement_publisherIdMismatch_fails() {
    ReferenceValues refValues = withPublisherId("unauthorized-publisher@google.com");

    AttestationVerificationException exception =
        assertThrows(
            AttestationVerificationException.class,
            () ->
                verifier.verify(
                    VALID_TEST_TIMESTAMP_MILLIS, evidence, endorsements, refValues.toByteArray()));

    assertThat(exception.getMessage()).contains("publisher_id");
    assertThat(exception.getMessage()).contains("required claim not found");
  }

  @Test
  public void
      testOakVerifier_pesEndorsement_multipleSignaturesInPublicEndorsement_firstValidSecondUntrustedKey_succeeds()
          throws Exception {
    // Simulates the start of PES key rotation when PES dual-signs with [active_trusted_key,
    // new_untrusted_key] before the new key is added to key_set (b/565672521).
    byte[] dualSignedEndorsements =
        withEndorsementSignatures(List.of(validPesSignatureJson, untrustedKeyPesSignatureJson));

    AttestationResults results =
        verifier.verify(
            VALID_TEST_TIMESTAMP_MILLIS,
            evidence,
            dualSignedEndorsements,
            baseReferenceValues.toByteArray());

    assertThat(results.getStatus()).isEqualTo(AttestationResults.Status.STATUS_SUCCESS);
  }

  @Test
  public void
      testOakVerifier_pesEndorsement_multipleSignaturesInPublicEndorsement_firstUntrustedKeySecondValid_succeeds()
          throws Exception {
    // Simulates dual-signed PublicEndorsement after an older PES signing key is retired from
    // key_set: signature[0] is signed by an untrusted key and signature[1] is signed by the active
    // trusted PES key (b/565672521).
    byte[] dualSignedEndorsements =
        withEndorsementSignatures(List.of(untrustedKeyPesSignatureJson, validPesSignatureJson));

    AttestationResults results =
        verifier.verify(
            VALID_TEST_TIMESTAMP_MILLIS,
            evidence,
            dualSignedEndorsements,
            baseReferenceValues.toByteArray());

    assertThat(results.getStatus()).isEqualTo(AttestationResults.Status.STATUS_SUCCESS);
  }

  @Test
  public void
      testOakVerifier_pesEndorsement_multipleSignaturesInPublicEndorsement_firstCorruptedSecondValid_succeeds()
          throws Exception {
    byte[] dualSignedEndorsements =
        withEndorsementSignatures(List.of(corruptedPesSignatureJson, validPesSignatureJson));

    AttestationResults results =
        verifier.verify(
            VALID_TEST_TIMESTAMP_MILLIS,
            evidence,
            dualSignedEndorsements,
            baseReferenceValues.toByteArray());

    assertThat(results.getStatus()).isEqualTo(AttestationResults.Status.STATUS_SUCCESS);
  }

  @Test
  public void
      testOakVerifier_pesEndorsement_multipleSignaturesInPublicEndorsement_allInvalid_fails()
          throws Exception {
    byte[] invalidDualSignedEndorsements =
        withEndorsementSignatures(List.of(untrustedKeyPesSignatureJson, corruptedPesSignatureJson));

    AttestationVerificationException exception =
        assertThrows(
            AttestationVerificationException.class,
            () ->
                verifier.verify(
                    VALID_TEST_TIMESTAMP_MILLIS,
                    evidence,
                    invalidDualSignedEndorsements,
                    baseReferenceValues.toByteArray()));

    assertThat(exception.getMessage()).contains("failed to verify any PES endorsement signature");
    assertThat(exception.getMessage()).contains("signature[0]");
    assertThat(exception.getMessage()).contains("PES public key not found in trusted key set");
    assertThat(exception.getMessage()).contains("signature[1]");
    assertThat(exception.getMessage()).contains("failed to verify RSA signature");
  }
}
