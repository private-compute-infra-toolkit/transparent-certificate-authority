/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.tca.server;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import software.amazon.awssdk.imds.Ec2MetadataClient;

/** Client for fetching metadata from AWS Instance Metadata Service (IMDS). */
public class ImdsClient {

  private static final String IDENTITY_DOCUMENT_PATH = "/latest/dynamic/instance-identity/document";
  private static final String ENVIRONMENT_TAG_PATH = "/latest/meta-data/tags/instance/environment";
  private static final String DOMAIN_TAG_PATH = "/latest/meta-data/tags/instance/domain";

  public ImdsClient() {}

  /**
   * Fetches the EC2 Instance Identity Document and returns an {@link AwsInstanceMetadata}.
   *
   * @return the {@link AwsInstanceMetadata} containing region and account ID.
   * @throws RuntimeException if the fetch fails.
   */
  public AwsInstanceMetadata getAwsInstanceMetadata() {
    try (Ec2MetadataClient client = Ec2MetadataClient.create()) {
      String docString = client.get(IDENTITY_DOCUMENT_PATH).asString();
      Gson gson = new Gson();
      JsonObject identityDocument = gson.fromJson(docString, JsonObject.class);
      String region = identityDocument.get("region").getAsString();
      String accountId = identityDocument.get("accountId").getAsString();
      String instanceId = identityDocument.get("instanceId").getAsString();

      String environment = client.get(ENVIRONMENT_TAG_PATH).asString();
      String domain = client.get(DOMAIN_TAG_PATH).asString();

      return AwsInstanceMetadata.builder()
          .setRegion(region)
          .setAccountId(accountId)
          .setEnvironment(environment)
          .setDomain(domain)
          .setInstanceId(instanceId)
          .build();
    } catch (Exception e) {
      throw new RuntimeException("Failed to fetch EC2 Instance Identity Document via IMDS.", e);
    }
  }
}
