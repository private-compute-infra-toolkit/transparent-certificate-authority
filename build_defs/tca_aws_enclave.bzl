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

"""TCA-specific wrappers for AWS enclave AMI generation."""

load("@rules_aws//build_defs/aws/enclave:aws_eif_and_ami.bzl", "aws_eif_and_ami")

def tca_aws_eif_and_ami(
        name,
        enable_worker_debug_mode = False,
        uninstall_ssh_server = False,
        jar_args = [],
        extra_container_tars = [],
        extra_jvm_options = [],
        ami_name = ":ami_name_flag",
        aws_region = ":aws_region_flag",
        subnet_id = ":subnet_id_flag",
        jar_file = "/server_main_deploy.jar",
        jar_path = "//java/com/google/tca/server:server_main_deploy.jar",
        service_name = "tca",
        user_rpms = [],
        **kwargs):
    """Generates a TCA-specific AWS EIF and AMI with standard defaults.

    Args:
        name: The target name.
        enable_worker_debug_mode: Whether worker debug mode is enabled. Defaults to False.
        uninstall_ssh_server: Whether to uninstall SSH server. Defaults to False.
        jar_args: The arguments to pass to the service JAR.
        extra_container_tars: Extra container layer tars to package into the EIF.
        extra_jvm_options: Extra JVM options to append to standard TCA defaults.
        ami_name: Target label for the AMI name. Defaults to ":ami_name_flag".
        aws_region: Target label for the AWS region. Defaults to ":aws_region_flag".
        subnet_id: Target label for the VPC subnet ID. Defaults to ":subnet_id_flag".
        jar_file: Target file name inside the enclave. Defaults to "/server_main_deploy.jar".
        jar_path: Label of the target JAR binary. Defaults to "//java/com/google/tca/server:server_main_deploy.jar".
        service_name: The name of the systemd service. Defaults to "tca".
        **kwargs: Additional arguments to pass to the underlying aws_eif_and_ami.
    """
    default_additional_container_tars = [
        "//java/com/google/tca/attestation/oak/jni:oak_attestation_verifier_jni_tar",
        "@pcit_mbs//java/com/google/mbs:nsm_jni_tar",
    ]

    default_jvm_options = [
        "-Dlogging.host=localhost",
        "-Dlogging.port=50052",
        "-Dflogger.backend_factory=com.google.common.flogger.backend.slf4j.Slf4jBackendFactory",
    ]

    default_user_rpms = [
        "//build_defs/aws:tca_metrics_rpm",
    ]

    aws_eif_and_ami(
        name = name,
        additional_container_tars = default_additional_container_tars + extra_container_tars,
        ami_name = ami_name,
        aws_region = aws_region,
        enable_worker_debug_mode = enable_worker_debug_mode,
        jar_args = jar_args,
        jar_file = jar_file,
        jar_path = jar_path,
        jvm_options = default_jvm_options + extra_jvm_options,
        service_name = service_name,
        subnet_id = subnet_id,
        uninstall_ssh_server = uninstall_ssh_server,
        user_rpms = default_user_rpms + user_rpms,
        **kwargs
    )
