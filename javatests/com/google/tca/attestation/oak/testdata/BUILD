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

load(":generation.bzl", "generate_attestation_data")

package(default_visibility = ["//visibility:public"])

generate_attestation_data(
    name = "milan_attestation_data",
    file_name_prefix = "milan_oc_release",
)

generate_attestation_data(
    name = "fake_attestation_data",
    file_name_prefix = "fake",
)

filegroup(
    name = "manual_attestation_data",
    srcs = [
        "certificate_signing_request.pem",
        "manual_oak_attestation_evidence.textproto",
        "manual_oak_reference_values.textproto",
        "manual_oak_reference_values_regex.textproto",
        "manual_oak_reference_values_regex_mismatch.textproto",
    ],
)
