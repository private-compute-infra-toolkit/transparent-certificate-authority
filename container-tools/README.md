# PCIT Container Tools

## Overview

**PCIT Container Tools** (Private Compute Infrastructure Toolkit) is a shared repository providing tooling, libraries, and build definitions for containerized workloads. It is primarily designed to support Trusted Execution Environments (TEEs), specifically focusing on building Amazon Machine Images (AMIs) and **AWS Nitro Enclaves**.

This repository serves as a foundational, reusable library consumed by other services.

## Core Capabilities

- **AMI and EIF Generation:** Provides the necessary infrastructure, Bazel rules, and templates for building Amazon Machine Images (AMIs) and Enclave Image Files (EIFs) for AWS.
- **Shared Dependencies:** Acts as a common dependency for other services, offering standardized Bazel build rules and core utilities used across the toolkit.

## Repository Structure

At a high level, the repository is organized into the following areas:

- `build_defs/`: Shared Bazel build definitions, macros, and rules.
- `cc/`: Common utilities that are included in the deployed AMIs.
- `operator/`: Build rules and HashiCorp Packer configurations for baking worker AMIs.

## Building and Testing

This project uses [Bazel](https://bazel.build/) as its primary build system.

To build the entire repository:

```bash
bazel build //...
```

To run all tests:

```bash
bazel test //...
```

## Optional Security Integrations (CrowdStrike Falcon)

This repository supports baking the CrowdStrike Falcon sensor directly into the parent host AMI during image provisioning.

By default, this integration is **disabled** (all configuration flags default to `""`), allowing open-source builds to succeed out-of-the-box.

To enable and configure the sensor, override the following Bazel flags (e.g., in a `.bazelrc` file or on the command line):

- `--@rules_aws//build_defs:crowdstrike_cid`: The CrowdStrike Customer ID (CID). A non-empty value triggers the installation.
- `--@rules_aws//build_defs:crowdstrike_bucket`: The private S3 bucket holding the sensor RPM.
- `--@rules_aws//build_defs:crowdstrike_key`: The S3 object key (filename) of the RPM.
- `--@rules_aws//build_defs:crowdstrike_sha256`: The SHA256 checksum to verify the downloaded RPM.
- `--@rules_aws//build_defs:pcit_packer_iam_instance_profile`: The IAM Instance Profile (role) to attach to the Packer builder instance for S3 read permissions.
