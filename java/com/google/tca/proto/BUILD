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

load("@com_google_protobuf//bazel:java_proto_library.bzl", "java_proto_library")
load("@io_grpc_grpc_java//:java_grpc_library.bzl", "java_grpc_library")

package(default_visibility = ["//visibility:public"])

java_proto_library(
    name = "transparent_certificate_authority_java_proto",
    deps = ["@pcit_api//google/tca/v1:transparent_certificate_authority_proto"],
)

java_grpc_library(
    name = "transparent_certificate_authority_java_grpc",
    srcs = [
        "@pcit_api//google/tca/v1:transparent_certificate_authority_proto",
    ],
    deps = [
        ":transparent_certificate_authority_java_proto",
    ],
)

java_proto_library(
    name = "tca_policy_java_proto",
    deps = [
        "@pcit_api//google/tca/policy/v2:tca_policy_proto",
    ],
)
