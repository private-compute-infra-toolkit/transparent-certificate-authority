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

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnit;
import org.mockito.junit.MockitoRule;

@RunWith(JUnit4.class)
public class AwsResourceNamesProviderTest {

  @Rule public final MockitoRule mockito = MockitoJUnit.rule();

  @Mock private KmsArgs mockKmsArgs;
  private AwsResourceNamesProvider provider;

  @Before
  public void setUp() {
    when(mockKmsArgs.getCertBackupBucketPrefix()).thenReturn("test-cert-backup-prefix");
    when(mockKmsArgs.getKeyBackupBucketPrefix()).thenReturn("test-key-backup-prefix");
    when(mockKmsArgs.getConfigBucketPrefix()).thenReturn("test-config-prefix");
    when(mockKmsArgs.getKmsKeySuffix()).thenReturn("alias/test-key-suffix");

    AwsInstanceMetadata awsInstanceMetadata =
        AwsInstanceMetadata.builder()
            .setRegion("us-east-1")
            .setAccountId("123456789012")
            .setEnvironment("dev")
            .setDomain("pcit.goog")
            .setInstanceId("i-testinstance")
            .build();
    provider = new AwsResourceNamesProvider(mockKmsArgs, awsInstanceMetadata);
  }

  @Test
  public void getRecord_composesCorrectly() {
    AwsResourceNames record = provider.getRecord();

    assertEquals("test-cert-backup-prefix-123456789012-us-east-1", record.certBackupBucketName());
    assertEquals("test-key-backup-prefix-123456789012-us-east-1", record.keyBackupBucketName());
    assertEquals("test-config-prefix-123456789012-us-east-1", record.configBucketName());
    assertEquals("arn:aws:kms:us-east-1:123456789012:alias/test-key-suffix", record.kmsKeyArn());
  }
}
