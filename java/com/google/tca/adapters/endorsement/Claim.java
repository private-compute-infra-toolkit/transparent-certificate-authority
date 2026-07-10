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

package com.google.tca.adapters.endorsement;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Map;

/**
 * Represents a claim within an Oak endorsement statement.
 *
 * @see <a href="https://project-oak.github.io/oak/tr/endorsement/v1">Oak Endorsement
 *     Specification</a>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Claim {
  public static final String PES_CLAIM_PUBLISHER_TYPE =
      "https://github.com/private-compute-infra-toolkit/public-endorsement-service/blob/main/docs/claims/publisher.md";
  public static final String PUBLISHER_ID_KEY = "publisher_id";
  public static final String WORKLOAD_CLAIM_TYPE =
      "https://github.com/private-compute-infra-toolkit/public-endorsement-service/blob/main/docs/claims/workload.md";
  public static final String WORKLOAD_ID_KEY = "workload_id";

  private final String type;
  private final Map<String, String> annotations;

  @JsonCreator
  public Claim(
      @JsonProperty(value = "type", required = true) String type,
      @JsonProperty(value = "annotations") Map<String, String> annotations) {
    if (type == null) {
      throw new IllegalArgumentException("Claim type is null");
    }

    if (type.equals(PES_CLAIM_PUBLISHER_TYPE)) {
      validatePublisherClaim(annotations);
    } else if (type.equals(WORKLOAD_CLAIM_TYPE)) {
      validateWorkloadClaim(annotations);
    }

    this.type = type;
    this.annotations = annotations;
  }

  private void validatePublisherClaim(Map<String, String> annotations) {
    if (annotations == null || annotations.get(PUBLISHER_ID_KEY) == null) {
      throw new IllegalArgumentException(
          String.format(
              "Publisher claim needs to have annotations object with %s key!", PUBLISHER_ID_KEY));
    }
  }

  private void validateWorkloadClaim(Map<String, String> annotations) {
    if (annotations == null || annotations.get(WORKLOAD_ID_KEY) == null) {
      throw new IllegalArgumentException(
          String.format(
              "Workload claim needs to have annotations object with %s key!", WORKLOAD_ID_KEY));
    }
  }

  public String getType() {
    return type;
  }

  public Map<String, String> getAnnotations() {
    return annotations;
  }
}
