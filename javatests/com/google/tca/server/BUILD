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

load("@rules_java//java:defs.bzl", "java_library", "java_test")

filegroup(
    name = "test_resources",
    srcs = [
        "testdata/golden_request.textproto",
        "testdata/policy/v1/policy.textproto",
        "testdata/policy/v2/policy.textproto",
        "testdata/reference_values.textproto",
        "testdata/test_tca_config.json",
        "testdata/test_tca_config.json.sigstore.json",
        "testdata/test_tca_config_modified.json",
        "testdata/trusted_root.json",
    ],
    visibility = [
        "//javatests/com/google/tca/server:__subpackages__",
    ],
)

java_library(
    name = "FileFetcherStub",
    srcs = [
        "FileFetcherStub.java",
    ],
    runtime_deps = [
        "@maven//:com_google_flogger_flogger_system_backend",
    ],
    deps = [
        "//java/com/google/tca/domain",
        "@maven//:com_google_flogger_flogger",
        "@maven//:com_google_protobuf_protobuf_java",
    ],
)

java_library(
    name = "RequestUtils",
    srcs = [
        "RequestUtils.java",
    ],
    runtime_deps = [
        "@maven//:com_google_flogger_flogger_system_backend",
    ],
    deps = [
        "//java/com/google/tca/adapters",
        "//java/com/google/tca/domain",
        "@maven//:com_google_flogger_flogger",
        "@maven//:com_google_protobuf_protobuf_java",
        "@maven//:io_jsonwebtoken_jjwt_api",
        "@maven//:io_jsonwebtoken_jjwt_impl",
        "@maven//:io_jsonwebtoken_jjwt_jackson",
        "@oak//proto:variant_java_proto",
        "@oak//proto/attestation:endorsement_java_proto",
        "@oak//proto/attestation:evidence_java_proto",
    ],
)

java_library(
    name = "GoldenRequest",
    srcs = [
        "GoldenRequest.java",
    ],
    runtime_deps = [
        "@maven//:com_google_flogger_flogger_system_backend",
    ],
    deps = [
        "//java/com/google/tca/domain",
        "//java/com/google/tca/proto:transparent_certificate_authority_java_grpc",
        "//java/com/google/tca/proto:transparent_certificate_authority_java_proto",
        "@maven//:com_google_flogger_flogger",
        "@maven//:com_google_protobuf_protobuf_java",
        "@oak//proto/attestation:endorsement_java_proto",
        "@oak//proto/attestation:evidence_java_proto",
    ],
)

java_test(
    name = "CertificateIssuanceIntegrationTest",
    size = "medium",
    srcs = [
        "CertificateIssuanceIntegrationTest.java",
    ],
    data = [
        ":test_resources",
        "//javatests/com/google/tca/attestation/oak/testdata:certificate_signing_request.pem",
        "//javatests/com/google/tca/attestation/oak/testdata:manual_oak_attestation_evidence.textproto",
    ],
    resources = [":test_resources"],
    deps = [
        ":FileFetcherStub",
        ":RequestUtils",
        "//java/com/google/tca/adapters/oidc",
        "//java/com/google/tca/domain",
        "//java/com/google/tca/domain/attestation",
        "//java/com/google/tca/domain/policy",
        "//java/com/google/tca/proto:transparent_certificate_authority_java_grpc",
        "//java/com/google/tca/proto:transparent_certificate_authority_java_proto",
        "//java/com/google/tca/server",
        "//java/com/google/tca/server:cmd_line_args",
        "//java/com/google/tca/server:metadata",
        "@com_google_protobuf//:protobuf_javalite",
        "@io_grpc_grpc_java//api",
        "@io_grpc_grpc_java//inprocess",
        "@io_grpc_grpc_java//stub",
        "@io_grpc_grpc_java//testing",
        "@maven//:com_google_guava_guava",
        "@maven//:com_google_inject_extensions_guice_testlib",
        "@maven//:com_google_inject_guice",
        "@maven//:com_google_truth_truth",
        "@maven//:io_jsonwebtoken_jjwt_api",
        "@maven//:io_micrometer_micrometer_registry_prometheus",
        "@maven//:junit_junit",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
        "@maven//:org_mockito_mockito_core",
        "@oak//proto/attestation:endorsement_java_proto",
        "@oak//proto/attestation:evidence_java_proto",
        "@pcit_mbs//java/com/google/mbs:certmanagement",
        "@pcit_mbs//java/com/google/mbs/attestationcollection",
    ],
)

java_test(
    name = "FullIntegrationTest",
    size = "medium",
    srcs = [
        "FullIntegrationTest.java",
    ],
    data = [
        ":test_resources",
        "//javatests/com/google/tca/attestation/oak/testdata:certificate_signing_request.pem",
        "//javatests/com/google/tca/attestation/oak/testdata:manual_oak_attestation_evidence.textproto",
    ],
    resources = [":test_resources"],
    deps = [
        ":GoldenRequest",
        ":RequestUtils",
        "//java/com/google/tca/adapters",
        "//java/com/google/tca/adapters/oidc",
        "//java/com/google/tca/domain",
        "//java/com/google/tca/domain/attestation",
        "//java/com/google/tca/domain/metric",
        "//java/com/google/tca/domain/policy",
        "//java/com/google/tca/proto:transparent_certificate_authority_java_grpc",
        "//java/com/google/tca/proto:transparent_certificate_authority_java_proto",
        "//java/com/google/tca/server",
        "//java/com/google/tca/server:cmd_line_args",
        "//java/com/google/tca/server:metadata",
        "@com_google_protobuf//:protobuf_javalite",
        "@com_google_protobuf//java/core",
        "@io_grpc_grpc_java//api",
        "@io_grpc_grpc_java//inprocess",
        "@io_grpc_grpc_java//stub",
        "@io_grpc_grpc_java//testing",
        "@maven//:com_google_guava_guava",
        "@maven//:com_google_inject_extensions_guice_testlib",
        "@maven//:com_google_inject_guice",
        "@maven//:com_google_truth_truth",
        "@maven//:com_linecorp_armeria_armeria",
        "@maven//:io_jsonwebtoken_jjwt_api",
        "@maven//:io_micrometer_micrometer_registry_prometheus",
        "@maven//:junit_junit",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
        "@maven//:org_mockito_mockito_core",
        "@maven//:org_testcontainers_localstack",
        "@maven//:org_testcontainers_testcontainers",
        "@maven//:software_amazon_awssdk_auth",
        "@maven//:software_amazon_awssdk_regions",
        "@maven//:software_amazon_awssdk_s3",
        "@maven//:software_amazon_awssdk_sdk_core",
        "@oak//proto/attestation:endorsement_java_proto",
        "@oak//proto/attestation:evidence_java_proto",
        "@pcit_mbs//java/com/google/mbs:certmanagement",
        "@pcit_mbs//java/com/google/mbs/attestationcollection",
    ],
)

java_test(
    name = "KmsModeModuleTest",
    size = "small",
    srcs = [
        "KmsModeModuleTest.java",
    ],
    deps = [
        "//java/com/google/tca/server",
        "//java/com/google/tca/server:cmd_line_args",
        "//java/com/google/tca/server:metadata",
        "@maven//:com_google_guava_guava",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
        "@maven//:org_mockito_mockito_core",
        "@maven//:software_amazon_awssdk_s3",
        "@pcit_mbs//java/com/google/kmsclient",
        "@pcit_mbs//java/com/google/mbs:certmanagement",
        "@pcit_mbs//java/com/google/mbs/attestationcollection",
        "@pcit_mbs//java/com/google/tlog",
    ],
)

java_test(
    name = "AwsResourceNamesProviderTest",
    size = "small",
    srcs = ["AwsResourceNamesProviderTest.java"],
    deps = [
        "//java/com/google/tca/server",
        "//java/com/google/tca/server:cmd_line_args",
        "//java/com/google/tca/server:metadata",
        "@maven//:junit_junit",
        "@maven//:org_mockito_mockito_core",
    ],
)

java_test(
    name = "CertificateIssuanceComponentTest",
    size = "small",
    srcs = ["CertificateIssuanceComponentTest.java"],
    data = [":test_resources"],
    resources = [":test_resources"],
    deps = [
        ":FileFetcherStub",
        ":RequestUtils",
        "//java/com/google/tca/adapters",
        "//java/com/google/tca/domain",
        "//java/com/google/tca/domain/attestation",
        "//java/com/google/tca/domain/policy",
        "//java/com/google/tca/server",
        "//java/com/google/tca/server:cmd_line_args",
        "@com_google_protobuf//:protobuf_javalite",
        "@maven//:com_google_guava_guava",
        "@maven//:com_google_inject_guice",
        "@maven//:com_google_truth_truth",
        "@maven//:jakarta_inject_jakarta_inject_api",
        "@maven//:junit_junit",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
        "@maven//:org_mockito_mockito_core",
        "@oak//proto/attestation:endorsement_java_proto",
        "@oak//proto/attestation:evidence_java_proto",
        "@pcit_mbs//java/com/google/mbs:certmanagement",
    ],
)

java_test(
    name = "CertificateValidityReporterTest",
    size = "small",
    srcs = ["CertificateValidityReporterTest.java"],
    deps = [
        "//java/com/google/tca/domain",
        "//java/com/google/tca/domain/metric",
        "//java/com/google/tca/server",
        "@maven//:com_google_guava_guava",
        "@maven//:com_google_truth_truth",
        "@maven//:junit_junit",
        "@maven//:org_mockito_mockito_core",
    ],
)
