#!/bin/bash
# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -e

# Setup SSM Agent
sudo yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm

sudo yum install docker-24.0.5-1.amzn2023.0.3 -y
sudo systemctl enable docker
sudo systemctl start docker

# shellcheck disable=SC1083
sudo docker load --input /tmp/{container_file}

sudo yum install aws-nitro-enclaves-cli -y
sudo yum install python -y
sudo yum install python3-yaml -y

sudo yum install aws-nitro-enclaves-cli-devel -y
sudo systemctl enable nitro-enclaves-allocator.service

sudo rpm -i /tmp/rpms/*.rpm

# Configure and start CrowdStrike Falcon if a CID is provided
CROWDSTRIKE_CID="{crowdstrike_cid}"
if [[ -n "${CROWDSTRIKE_CID}" ]]; then
  if [[ ! "${CROWDSTRIKE_CID}" =~ ^[0-9A-Fa-f]{32}-[0-9A-Fa-f]{2}$ ]]; then
    echo "ERROR: Invalid CrowdStrike Customer ID format: '${CROWDSTRIKE_CID}'."
    exit 1
  fi

  echo "Downloading CrowdStrike Falcon..."
  aws s3 cp "s3://{crowdstrike_bucket}/{crowdstrike_key}" /tmp/falcon-sensor.rpm
  echo "{crowdstrike_sha256}  /tmp/falcon-sensor.rpm" | sha256sum --check

  sudo dnf install --disablerepo="*" /tmp/falcon-sensor.rpm -y
  sudo /opt/CrowdStrike/falconctl -s --cid="${CROWDSTRIKE_CID}"
  sudo systemctl enable falcon-sensor
  sudo /opt/CrowdStrike/falconctl -d -f --aid
  rm -f /tmp/falcon-sensor.rpm
fi

# Install Fluent Bit via package manager
sudo yum install fluent-bit -y

# Overwrite default Fluent Bit config with our custom one installed by the RPM
sudo cp /opt/google/enclave/fluent-bit.conf /etc/fluent-bit/fluent-bit.conf

# Enable Fluent Bit service
sudo systemctl enable fluent-bit

# Enable the configuration service (installed by RPM)
sudo systemctl enable configure-fluent-bit.service

sudo yum install amazon-cloudwatch-agent -y

sudo systemctl enable metrics-exporter.service

sudo systemctl enable vsockproxy

sudo systemctl enable enclave

# This script runs in the boot phase in which environment variables are not set.
# This variable is needed to run nitro-cli build-enclave.
export NITRO_CLI_ARTIFACTS="/tmp/enclave-images/"

# shellcheck disable=SC1083
sudo nitro-cli build-enclave --docker-uri bazel:{docker_tag} --output-file /opt/google/enclave/enclave.eif

# Move config files which require elevated permissions.
# https://github.com/hashicorp/packer/issues/1551#issuecomment-59131451
sudo mv /tmp/allocator.yaml /etc/nitro_enclaves/allocator.yaml
sudo mkdir /licenses
sudo tar xf /tmp/licenses.tar -C /licenses
