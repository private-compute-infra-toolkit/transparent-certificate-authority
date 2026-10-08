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
    name = "OakAttestationVerifierTest",
    size = "small",
    srcs = ["OakAttestationVerifierTest.java"],
    data = [
        "//javatests/com/google/tca/attestation/oak/testdata:manual_attestation_data",
    ],
    deps = [
        "//java/com/google/tca/adapters",
        "//java/com/google/tca/attestation/oak",
        "//java/com/google/tca/domain/attestation",
        "//java/com/google/tca/domain/policy",
        "//java/com/google/tca/proto:transparent_certificate_authority_java_proto",
        "@maven//:com_google_crypto_tink_tink",
        "@maven//:com_google_protobuf_protobuf_java",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
        "@maven//:org_mockito_mockito_core",
        "@oak//proto/attestation:endorsement_java_proto",
        "@oak//proto/attestation:evidence_java_proto",
        "@oak//proto/attestation:reference_value_java_proto",
        "@oak//proto/attestation:verification_java_proto",
    ],
)

java_test(
    name = "OakEvidenceVerifierTest",
    size = "small",
    srcs = ["OakEvidenceVerifierTest.java"],
    data = [
        "//javatests/com/google/tca/attestation/oak/testdata:fake_attestation_data",
        "//javatests/com/google/tca/attestation/oak/testdata:milan_attestation_data",
    ],
    deps = [
        "//java/com/google/tca/attestation/oak",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@oak//proto/attestation:verification_java_proto",
    ],
)

java_test(
    name = "OakPesEndorsementVerifierTest",
    size = "small",
    srcs = ["OakPesEndorsementVerifierTest.java"],
    data = [
        "//javatests/com/google/tca/attestation/oak/testdata:pes_endorsement_reference_values.textproto",
        "//javatests/com/google/tca/server:attestation_test_resources",
    ],
    deps = [
        "//java/com/google/tca/adapters",
        "//java/com/google/tca/attestation/oak",
        "//java/com/google/tca/proto:transparent_certificate_authority_java_proto",
        "@maven//:com_google_code_gson_gson",
        "@maven//:com_google_protobuf_protobuf_java",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@oak//proto:variant_java_proto",
        "@oak//proto/attestation:endorsement_java_proto",
        "@oak//proto/attestation:evidence_java_proto",
        "@oak//proto/attestation:reference_value_java_proto",
        "@oak//proto/attestation:verification_java_proto",
    ],
)
