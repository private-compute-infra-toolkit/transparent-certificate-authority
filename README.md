# Transparent Certificate Authority (TCA)

The Transparent Certificate Authority (TCA) is a system designed to issue certificates to software
workloads running inside Trusted Execution Environments (TEEs). These certificates provide strong,
cryptographically verifiable identities, which are essential for establishing secure communication
channels, such as mutual TLS, between distributed services, regardless of the underlying
infrastructure.

## Core Concepts

-   **Trusted Execution Environment (TEE):** A secure area within a processor, often
    hardware-isolated, designed to protect code and data from unauthorized access or modification.
    TEEs provide integrity and confidentiality guarantees, allowing external parties to remotely
    verify the software state.
-   **Workload Attestation:** The process by which a TEE can cryptographically prove its current
    software and hardware state to a relying party. Platform providers typically offer attestation
    services that generate signed statements (attestation tokens) about the TEE's status.
-   **X509 Certificates:** A standard format for public key certificates used in many security
    protocols, including TLS. TCA issues these certificates to bind public keys to attested workload
    identities.
-   **Mutual TLS (mTLS):** A security protocol where both client and server authenticate each other
    using certificates. TCA-issued certificates enable workloads to establish mTLS connections.
-   **SPIFFE:** The Secure Production Identity Framework For Everyone, a set of open standards for
    securely issuing and verifying identities for software services. TCA often issues certificates
    with SPIFFE ID URIs as Subject Alternative Names.
-   **Key Management Service (KMS):** A secure service for creating, managing, and controlling
    cryptographic keys (such as AWS KMS).

## How TCA Works

The TCA system provides a full lifecycle for certificate management for TEE workloads, from secure
bootstrapping to certificate issuance.

### Bootstrapping and Key Management

The TCA service itself is designed to run within a TEE to protect its sensitive Certificate
Authority signing keys. To ensure key material is not lost, private keys are encrypted and securely
stored using a Key Management Service (KMS), such as AWS KMS. Access to decrypt these keys is
strictly controlled based on the attestation of the TCA instance itself, ensuring only an authentic
TCA service can access the signing keys. Operations related to key access and management are
recorded in audit logs to support verifiable transparency.

### Certificate Issuance Flow

Workloads running in TEEs obtain certificates from the TCA through an attestation-based process:

1. **Key Generation & CSR:** The workload generates an asymmetric key pair within its TEE and
   creates a Certificate Signing Request (CSR) containing its public key.
2. **Attestation:** The workload requests an attestation token from the platform's attestation
   service. This token provides verifiable evidence of the workload's integrity and is
   cryptographically bound to the public key in the CSR.
3. **Request Submission:** The workload sends the CSR and the attestation token to the TCA service.
4. **Verification:** The TCA validates the signature and claims within the attestation token, using
   the public keys of the trusted platform attestation service. This confirms the workload is
   running in a legitimate TEE with the expected software.
5. **Identity Mapping:** The TCA consults a configuration policy to map low-level identifiers from
   the attestation token (e.g., software image digests or their endorsements) to a standardized,
   recognizable service identity, such as a SPIFFE ID.
6. **Certificate Issuance:** Upon successful validation and policy checks, the TCA signs the CSR
   with its private key, generating a certificate. This certificate is returned to the workload.

### Extensible Attestation Architecture

The TCA is designed to be platform-agnostic. It uses an extensible framework to support various
attestation services and token formats from different TEE providers. Currently,
[Project Oak Containers](https://github.com/project-oak/oak) is the primary supported open-source
platform.

## Key Features

-   **Enhanced Security:** Leverages TEEs for both the TCA service and the workloads, protecting
    keys and the certificate issuance process.
-   **Standardized Identities:** Issues X509 certificates. The workload identity is included as a
    SPIFFE ID URI in the certificate's Subject Alternative Name (SAN) extension.
-   **Transparency:** Key events such as CA key generation, certificate issuance, and policy changes
    are logged to tamper-evident storage and auditable transparency logs. This is achieved by AWS
    features set up outside of this repository using Terraform.

## Benefits

-   **Zero Trust Enablement:** Provides strong, hardware-backed identities for workloads, a
    cornerstone of Zero Trust security models.
-   **Secure Inter-Service Communication:** Enables robust mTLS authentication between microservices
    or components running in TEEs.
-   **Improved Compliance and Auditability:** Offers verifiable proof of workload integrity and
    transparent CA operations.
