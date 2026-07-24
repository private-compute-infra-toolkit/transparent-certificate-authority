# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

load("@rules_java//java:defs.bzl", "java_test")

package(default_visibility = ["//visibility:public"])

java_test(
    name = "OidcJwksKeyFetcherTest",
    size = "small",
    srcs = ["OidcJwksKeyFetcherTest.java"],
    deps = [
        "//java/com/google/tca/adapters/oidc",
        "//java/com/google/tca/domain/metric",
        "@maven//:com_fasterxml_jackson_core_jackson_databind",
        "@maven//:com_google_guava_guava",
        "@maven//:com_google_truth_truth",
        "@maven//:com_squareup_okhttp3_mockwebserver",
        "@maven//:junit_junit",
        "@maven//:org_mockito_mockito_core",
    ],
)

java_test(
    name = "OidcAudienceBindingValidatorTest",
    size = "small",
    srcs = ["OidcAudienceBindingValidatorTest.java"],
    deps = [
        "//java/com/google/tca/adapters/oidc",
        "//java/com/google/tca/domain",
        "//java/com/google/tca/server:metadata",
        "@maven//:com_google_guava_guava",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_mockito_mockito_core",
    ],
)
