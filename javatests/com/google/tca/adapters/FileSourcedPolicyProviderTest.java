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

package com.google.tca.adapters;

import static com.google.common.truth.Truth.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.google.protobuf.ByteString;
import com.google.tca.domain.CallerIdentity;
import com.google.tca.domain.FileFetcher;
import com.google.tca.domain.metric.Metrics;
import com.google.tca.domain.policy.Policy;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Collection;
import java.util.Optional;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;
import org.junit.runners.Parameterized.Parameters;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

@RunWith(Parameterized.class)
public class FileSourcedPolicyProviderTest {

  @Parameters(name = "{0}")
  public static Collection<Object[]> data() {
    return Arrays.asList(
        new Object[][] {
          {"javatests/com/google/tca/adapters/resources/policy/v2/test_policies.textproto"}
        });
  }

  @Parameter public String policyPath;

  @Mock private FileFetcher mockFileFetcher;
  @Mock private Metrics mockMetrics;

  private FileSourcedPolicyProvider policyProvider;

  @Before
  public void setUp() {
    MockitoAnnotations.initMocks(this);
    policyProvider = new FileSourcedPolicyProvider(mockFileFetcher, mockMetrics);
  }

  @Test
  public void getPolicy_whenFileFetches_mapsToTcaDomainPolicy() throws Exception {
    String fileContent = Files.readString(Paths.get(policyPath));
    String clientId = "test-client-id";
    when(mockFileFetcher.fetchFile(clientId))
        .thenReturn(Optional.of(ByteString.copyFromUtf8(fileContent)));

    CallerIdentity mockIdentity = mock(CallerIdentity.class);
    when(mockIdentity.getClientId()).thenReturn(clientId);
    when(mockIdentity.issuer()).thenReturn("");
    when(mockIdentity.subject()).thenReturn("");

    Optional<Policy> policyOpt =
        policyProvider.getPolicy(mockIdentity, "publisher-1@testpublisher.com", "workload-1");

    assertThat(policyOpt).isPresent();
    Policy policy = policyOpt.get();
    assertThat(policy.publisherId()).isEqualTo("publisher-1@testpublisher.com");
    assertThat(policy.workloadId()).isEqualTo("workload-1");
  }
}
