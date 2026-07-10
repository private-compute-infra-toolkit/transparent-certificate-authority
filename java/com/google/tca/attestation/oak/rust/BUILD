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

load("@cxx.rs//tools/bazel:rust_cxx_bridge.bzl", "rust_cxx_bridge")
load("@rules_rust//rust:defs.bzl", "rust_static_library")

package(default_visibility = ["//visibility:public"])

rust_static_library(
    name = "oak_verifier_rs",
    srcs = ["src/interface.rs"],
    deps = [
        "@crates//:cxx",
        "@oak//oak_attestation_verification:oak_attestation_verification_with_regex",
        "@oak//oak_attestation_verification_types",
        "@oak//oak_proto_rust",
        "@oak//oak_time",
        "@oak_std_crates_index//:anyhow",
        "@oak_std_crates_index//:prost",
    ],
)

rust_cxx_bridge(
    name = "oak_verifier_bridge",
    src = "src/interface.rs",
    deps = [
        ":oak_verifier_rs",
    ],
)
