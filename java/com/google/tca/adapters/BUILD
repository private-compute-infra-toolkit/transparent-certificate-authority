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

load("@rules_java//java:defs.bzl", "java_library", "java_plugin")

package(default_visibility = ["//visibility:public"])

java_plugin(
    name = "auto_value_plugin",
    processor_class = "com.google.auto.value.processor.AutoValueProcessor",
    deps = ["@maven//:com_google_auto_value_auto_value"],
)

java_library(
    name = "adapters",
    srcs = [
        "AttestationEvidenceMapper.java",
        "AttestationVerifierProviderImpl.java",
        "AwsAttestationEvidence.java",
        "CachedFileFetcher.java",
        "CertificateIssuanceRequestMapper.java",
        "CertificateSignerImpl.java",
        "DefaultTimeProvider.java",
        "FileSourcedPolicyProvider.java",
        "GcpAttestationEvidence.java",
        "KeyDecoderImpl.java",
        "OakAttestationEvidence.java",
        "PolicyBucket.java",
        "PolicyV2Mapper.java",
        "S3FileFetcher.java",
        "SystemMetrics.java",
    ],
    plugins = [":auto_value_plugin"],
    deps = [
        "//java/com/google/tca/attestation/common",
        "//java/com/google/tca/domain",
        "//java/com/google/tca/domain/attestation",
        "//java/com/google/tca/domain/metric",
        "//java/com/google/tca/domain/policy",
        "//java/com/google/tca/proto:tca_policy_java_proto",
        "//java/com/google/tca/proto:transparent_certificate_authority_java_proto",
        "@maven//:com_github_ben_manes_caffeine_caffeine",
        "@maven//:com_google_auto_value_auto_value_annotations",
        "@maven//:com_google_flogger_flogger",
        "@maven//:com_google_guava_guava",
        "@maven//:com_google_protobuf_protobuf_java",
        "@maven//:io_micrometer_micrometer_core",
        "@maven//:io_micrometer_micrometer_registry_prometheus",
        "@maven//:jakarta_inject_jakarta_inject_api",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
        "@maven//:software_amazon_awssdk_s3",
        "@maven//:software_amazon_awssdk_sdk_core",
        "@oak//proto:variant_java_proto",
        "@oak//proto/attestation:endorsement_java_proto",
        "@oak//proto/attestation:evidence_java_proto",
        "@pcit_mbs//java/com/google/mbs:certmanagement",
    ],
)
