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

package com.google.tca.server;

import com.google.protobuf.TextFormat;
import com.google.tca.v1.IssueCertificateRequest;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Instant;

public class GoldenRequest {
  Instant getNotBefore() {
    return Instant.parse("2026-06-25T14:52:25.941000Z");
  }

  Instant getNotAfter() {
    return Instant.parse("2026-09-22T12:53:03.582000Z");
  }

  public IssueCertificateRequest getRequestBody() throws Exception {

    String fullRequest =
        readTestFile("javatests/com/google/tca/server/testdata/golden_request.textproto");

    IssueCertificateRequest.Builder protoBuilder = IssueCertificateRequest.newBuilder();
    TextFormat.Parser parser = TextFormat.Parser.newBuilder().setAllowUnknownFields(true).build();
    parser.merge(fullRequest, protoBuilder);
    return protoBuilder.build();
  }

  String getPublisherId() {
    return "pcit-release-bot@google.com";
  }

  String getWorkloadId() {
    return "oak_tca_sdk_test_trusted_app";
  }

  String getVersion() {
    return "1";
  }

  private static String readTestFile(String path) throws Exception {
    return Files.readString(Paths.get(path));
  }
}
