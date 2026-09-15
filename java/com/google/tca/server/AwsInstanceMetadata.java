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

package com.google.tca.server;

import com.google.auto.value.AutoBuilder;

/** Immutable carrier for IMDS data. */
public record AwsInstanceMetadata(
    String region, String accountId, String environment, String domain, String instanceId) {

  public static Builder builder() {
    return new AutoBuilder_AwsInstanceMetadata_Builder();
  }

  /** Builder for {@link AwsInstanceMetadata}. */
  @AutoBuilder
  public interface Builder {
    Builder setRegion(String region);

    Builder setAccountId(String accountId);

    Builder setEnvironment(String environment);

    Builder setDomain(String domain);

    Builder setInstanceId(String instanceId);

    AwsInstanceMetadata build();
  }
}
