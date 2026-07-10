// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use anyhow::Context;
use oak_attestation_verification_types::verifier::AttestationVerifier;
use oak_proto_rust::oak::attestation::v1::{
    attestation_results::Status, AttestationResults, Endorsements, Evidence, ReferenceValues,
    TeePlatform
};
use oak_time::{clock::FixedClock, instant::Instant};

use prost::Message;

#[cxx::bridge(namespace = "com::google::tca::attestation::oak")]
mod ffi {
    extern "Rust" {
        /// Always returns a serialized AttestationResults protobuf, which contains
        /// the success or failure status.
        fn verify_attestation(
            now_utc_millis: i64,
            evidence_bytes: &[u8],
            endorsements_bytes: &[u8],
            reference_values_bytes: &[u8],
        ) -> Vec<u8>;
    }
}

/// The actual implementation of the bridged function.
fn verify_attestation(
    now_utc_millis: i64,
    evidence_bytes: &[u8],
    endorsements_bytes: &[u8],
    reference_values_bytes: &[u8],
) -> Vec<u8> {
    let result = verify_attestation_inner(
        now_utc_millis,
        evidence_bytes,
        endorsements_bytes,
        reference_values_bytes,
    );

    // Build AttestationResults based on whether the verification succeeded or failed.
    let attestation_results = match result {
        Ok(results) => AttestationResults {
            status: Status::Success.into(),
            event_attestation_results: results.event_attestation_results,
            ..Default::default()
        },
        Err(err) => AttestationResults {
            status: Status::GenericFailure.into(),
            reason: format!("{:#?}", err),
            ..Default::default()
        },
    };

    // Serialize the AttestationResults to bytes.
    attestation_results.encode_to_vec()
}

fn verify_attestation_inner(
    now_utc_millis: i64,
    evidence_bytes: &[u8],
    endorsements_bytes: &[u8],
    reference_values_bytes: &[u8],
) -> anyhow::Result<AttestationResults> {
    let evidence = Evidence::decode(evidence_bytes)?;
    let endorsements = Endorsements::decode(endorsements_bytes)?;
    let reference_values = ReferenceValues::decode(reference_values_bytes)?;

    let clock = FixedClock::at_instant(Instant::from_unix_millis(now_utc_millis));

    let root_layer = evidence
        .root_layer
        .as_ref()
        .context("extracting root layer from evidence")?;

    let verifier: Box<dyn AttestationVerifier> = match root_layer.platform() {
        TeePlatform::AmdSevSnp => Box::new(oak_attestation_verification_with_regex::create_amd_verifier(
            clock,
            &reference_values,
        )?),
        TeePlatform::IntelTdx => Box::new(oak_attestation_verification_with_regex::create_intel_tdx_verifier(
            clock,
            &reference_values,
        )?),
        TeePlatform::None => Box::new(oak_attestation_verification_with_regex::create_insecure_verifier(
            clock,
            &reference_values,
        )?),
        _ => anyhow::bail!(
            "unsupported root layer platform: {:?}",
            root_layer.platform()
        ),
    };

    verifier.verify(&evidence, &endorsements)
}
