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

load("@rules_java//java:defs.bzl", "java_binary", "java_library", "java_plugin")

java_plugin(
    name = "auto_value_plugin",
    processor_class = "com.google.auto.value.processor.AutoValueProcessor",
    deps = ["@maven//:com_google_auto_value_auto_value"],
)

java_plugin(
    name = "auto_builder_plugin",
    processor_class = "com.google.auto.value.processor.AutoBuilderProcessor",
    deps = ["@maven//:com_google_auto_value_auto_value"],
)

java_library(
    name = "cmd_line_args",
    srcs = [
        "HelpArgs.java",
        "KmsArgs.java",
        "LocalArgs.java",
    ],
    visibility = [
        "//javatests/com/google/tca/server:__subpackages__",
    ],
    deps = [
        "@maven//:com_beust_jcommander",
    ],
)

java_library(
    name = "server",
    srcs = [
        "AwsResourceNames.java",
        "AwsResourceNamesProvider.java",
        "CertificateValidityReporter.java",
        "ImdsClient.java",
        "JwtAuth.java",
        "JwtInterceptor.java",
        "KmsModeModule.java",
        "LocalModeModule.java",
        "TcaServer.java",
        "TransparentCaModule.java",
        "TransparentCertificateAuthorityGrpcHandler.java",
        "TrustedCertificateAuthorityGrpcHandler.java",
    ],
    plugins = [":auto_value_plugin"],
    visibility = ["//visibility:public"],
    deps = [
        ":cmd_line_args",
        ":metadata",
        "//java/com/google/tca/adapters",
        "//java/com/google/tca/adapters/certsigning",
        "//java/com/google/tca/adapters/endorsement",
        "//java/com/google/tca/adapters/oidc",
        "//java/com/google/tca/attestation/aws",
        "//java/com/google/tca/attestation/common",
        "//java/com/google/tca/attestation/gcp",
        "//java/com/google/tca/attestation/oak",
        "//java/com/google/tca/domain",
        "//java/com/google/tca/domain/attestation",
        "//java/com/google/tca/domain/metric",
        "//java/com/google/tca/proto:transparent_certificate_authority_java_grpc",
        "//java/com/google/tca/proto:transparent_certificate_authority_java_proto",
        "@com_google_protobuf//java/util",
        "@io_grpc_grpc_java//api",
        "@io_grpc_grpc_java//stub",
        "@io_grpc_grpc_proto//:health_java_proto",
        "@maven//:com_fasterxml_jackson_core_jackson_core",
        "@maven//:com_fasterxml_jackson_core_jackson_databind",
        "@maven//:com_google_auto_value_auto_value_annotations",
        "@maven//:com_google_code_findbugs_jsr305",
        "@maven//:com_google_code_gson_gson",
        "@maven//:com_google_flogger_flogger",
        "@maven//:com_google_guava_guava",
        "@maven//:com_google_inject_extensions_guice_assistedinject",
        "@maven//:com_google_inject_guice",
        "@maven//:com_google_protobuf_protobuf_java",
        "@maven//:com_linecorp_armeria_armeria",
        "@maven//:com_linecorp_armeria_armeria_grpc",
        "@maven//:com_linecorp_armeria_armeria_prometheus1",
        "@maven//:io_grpc_grpc_services",
        "@maven//:io_jsonwebtoken_jjwt_api",
        "@maven//:io_jsonwebtoken_jjwt_impl",
        "@maven//:io_jsonwebtoken_jjwt_jackson",
        "@maven//:io_micrometer_micrometer_core",
        "@maven//:io_micrometer_micrometer_registry_prometheus",
        "@maven//:jakarta_annotation_jakarta_annotation_api",
        "@maven//:jakarta_inject_jakarta_inject_api",
        "@maven//:org_bouncycastle_bcpkix_jdk18on",
        "@maven//:org_bouncycastle_bcprov_jdk18on",
        "@maven//:software_amazon_awssdk_imds",
        "@maven//:software_amazon_awssdk_regions",
        "@maven//:software_amazon_awssdk_s3",
        "@oak//proto/attestation:reference_value_java_proto",
        "@pcit_mbs//java/com/google/kmsclient",
        "@pcit_mbs//java/com/google/kmsclient/aws",
        "@pcit_mbs//java/com/google/mbs:certmanagement",
        "@pcit_mbs//java/com/google/mbs/attestationcollection",
        "@pcit_mbs//java/com/google/mbs/attestationcollection/aws",
        "@pcit_mbs//java/com/google/tlog",
    ],
)

genrule(
    name = "copy_logback_xml",
    srcs = ["@rules_aws//build_defs/aws/enclave:logback.xml"],
    outs = ["logback.xml"],
    cmd = "cp $< $@",
)

java_binary(
    name = "server_main",
    srcs = [
        "ServerMain.java",
    ],
    main_class = "com.google.tca.server.ServerMain",
    resource_strip_prefix = "java/com/google/tca/server",
    resources = [":logback.xml"],
    visibility = ["//visibility:public"],
    runtime_deps = [
        "@maven//:ch_qos_logback_logback_classic",
        "@maven//:ch_qos_logback_logback_core",
        "@maven//:com_google_flogger_flogger_slf4j_backend",
        "@maven//:net_logstash_logback_logstash_logback_encoder",
    ],
    deps = [
        ":cmd_line_args",
        ":server",
        "@io_grpc_grpc_java//api",
        "@io_grpc_grpc_proto//:health_java_proto",
        "@maven//:com_beust_jcommander",
        "@maven//:com_google_flogger_flogger",
        "@maven//:com_google_guava_guava",
        "@maven//:com_google_inject_guice",
        "@maven//:com_linecorp_armeria_armeria",
        "@maven//:com_linecorp_armeria_armeria_grpc",
        "@maven//:io_grpc_grpc_netty_shaded",
        "@maven//:io_grpc_grpc_services",
        "@maven//:io_micrometer_micrometer_registry_prometheus",
        "@maven//:software_amazon_awssdk_s3",
        "@pcit_mbs//java/com/google/kmsclient",
        "@pcit_mbs//java/com/google/kmsclient/aws",
        "@pcit_mbs//java/com/google/mbs:certmanagement",
        "@pcit_mbs//java/com/google/mbs/attestationcollection/aws",
        "@pcit_mbs//java/com/google/tlog",
    ],
)

java_library(
    name = "metadata",
    srcs = [
        "AwsInstanceMetadata.java",
    ],
    plugins = [
        ":auto_builder_plugin",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "@maven//:com_google_auto_value_auto_value_annotations",
    ],
)
