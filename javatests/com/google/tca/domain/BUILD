# Copyright 2025 Google LLC
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

java_test(
    name = "CallerIdentityTest",
    size = "small",
    srcs = ["CallerIdentityTest.java"],
    test_class = "com.google.tca.domain.CallerIdentityTest",
    deps = [
        "//java/com/google/tca/domain",
        "@maven//:junit_junit",
    ],
)

java_test(
    name = "TransparentCaServiceTest",
    size = "small",
    srcs = ["TransparentCaServiceTest.java"],
    test_class = "com.google.tca.domain.TransparentCaServiceTest",
    deps = [
        "//java/com/google/tca/domain",
        "//java/com/google/tca/domain/attestation",
        "//java/com/google/tca/domain/metric",
        "//java/com/google/tca/domain/policy",
        "@maven//:com_google_guava_guava",
        "@maven//:com_google_protobuf_protobuf_java",
        "@maven//:junit_junit",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
        "@maven//:org_mockito_mockito_core",
        "@pcit_mbs//java/com/google/mbs/domain",
    ],
)

java_test(
    name = "TrustDomainExtractorTest",
    size = "small",
    srcs = ["TrustDomainExtractorTest.java"],
    test_class = "com.google.tca.domain.TrustDomainExtractorTest",
    deps = [
        "//java/com/google/tca/domain",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
        "@maven//:org_mockito_mockito_core",
    ],
)
