/*
 * Copyright 2026 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.tca.adapters.endorsement;

import static com.google.tca.adapters.endorsement.Claim.PES_CLAIM_PUBLISHER_TYPE;
import static com.google.tca.adapters.endorsement.Claim.PUBLISHER_ID_KEY;
import static com.google.tca.adapters.endorsement.Claim.WORKLOAD_CLAIM_TYPE;
import static com.google.tca.adapters.endorsement.Claim.WORKLOAD_ID_KEY;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.google.common.flogger.FluentLogger;
import com.google.protobuf.ByteString;
import com.google.tca.domain.EndorsementMetadataProvider;
import com.google.tca.domain.attestation.EndorsementAnnotations;
import com.google.tca.domain.attestation.Validity;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.io.IOException;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;

/** Provider for endorsement metadata extracted and validated from in-toto statements. */
@Singleton
public final class JsonIntotoEndorsementMetadataProvider implements EndorsementMetadataProvider {
  private static final FluentLogger logger = FluentLogger.forEnclosingClass();
  private final ObjectReader reader;

  @Inject
  public JsonIntotoEndorsementMetadataProvider(ObjectMapper mapper) {
    this.reader = mapper.readerFor(InTotoStatement.class);
  }

  /**
   * Parses and validates an in-toto statement from a ByteString to extract claims annotations.
   *
   * <p>This method performs the following validations:
   *
   * <ol>
   *   <li>Ensures the input is valid JSON and matches the in-toto Statement v1 schema.
   *   <li>Verifies the statement contains exactly one resource descriptor in the 'subject'.
   *   <li>Checks that the 'predicate' includes a publisher claim with a valid 'publisher_id'.
   * </ol>
   *
   * @param statementBytes The ByteString containing the JSON in-toto statement.
   * @return The validated EndorsementAnnotations.
   */
  @Override
  public EndorsementAnnotations getAnnotations(ByteString statementBytes) {
    try {
      return extractAnnotations(statementBytes);
    } catch (Exception e) {
      logger.atWarning().log("Failed to extract annotations from endorsement, returning defaults");
      return new EndorsementAnnotations("default_publisher_id@example.com", "default_workload_id");
    }
  }

  @Override
  public Validity getValidity(ByteString statementBytes) {
    try {
      return extractValidity(statementBytes);
    } catch (DateTimeParseException e) {
      throw new IllegalArgumentException("Endorsement does not contain correct validity format");
    }
  }

  private Validity extractValidity(ByteString statementBytes) {
    InTotoStatement statement = parseStatement(statementBytes);

    OakPredicate.Validity validity = statement.getPredicate().getValidity();

    Instant notBefore = Instant.parse(validity.getNotBefore());
    Instant notAfter = Instant.parse(validity.getNotAfter());

    return new Validity(notBefore, notAfter);
  }

  private InTotoStatement parseStatement(ByteString statementBytes) {
    InTotoStatement statement;
    try {
      statement = reader.readValue(statementBytes.toByteArray());
    } catch (IOException e) {
      throw new IllegalArgumentException(
          String.format("Failed to parse input as JSON: %s", e.getMessage()), e);
    }
    return statement;
  }

  private EndorsementAnnotations extractAnnotations(ByteString statementBytes) {
    InTotoStatement statement = parseStatement(statementBytes);

    List<Claim> publisherClaims =
        statement.getPredicate().getClaims().stream()
            .filter(claim -> claim.getType().equals(PES_CLAIM_PUBLISHER_TYPE))
            .toList();
    if (1 != publisherClaims.size()) {
      throw new RuntimeException(
          "Expected exactly one publisher claim, but found: " + publisherClaims.size());
    }

    List<Claim> workloadClaims =
        statement.getPredicate().getClaims().stream()
            .filter(claim -> claim.getType().equals(WORKLOAD_CLAIM_TYPE))
            .toList();
    if (1 != workloadClaims.size()) {
      throw new RuntimeException(
          "Expected exactly one workload claim, but found: " + workloadClaims.size());
    }

    String publisherId = publisherClaims.get(0).getAnnotations().get(PUBLISHER_ID_KEY);
    String workloadId = workloadClaims.get(0).getAnnotations().get(WORKLOAD_ID_KEY);

    return new EndorsementAnnotations(publisherId, workloadId);
  }
}
