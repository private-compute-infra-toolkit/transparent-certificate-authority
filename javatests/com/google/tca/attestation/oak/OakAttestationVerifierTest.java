/*
 * Copyright 2025 Google LLC
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.google.tca.attestation.oak;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.assertThrows;

import com.google.protobuf.ByteString;
import com.google.protobuf.TextFormat;
import com.google.tca.adapters.AwsAttestationEvidence;
import com.google.tca.adapters.DefaultTimeProvider;
import com.google.tca.adapters.OakAttestationEvidence;
import com.google.tca.domain.attestation.AttestationEvidence;
import com.google.tca.domain.policy.ReferenceValues;
import com.google.tca.domain.policy.ReferenceValuesType;
import java.io.IOException;
import java.io.Reader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class OakAttestationVerifierTest {

  private static final String TEST_DATA_DIR = "javatests/com/google/tca/attestation/oak/testdata/";
  private final ReferenceValues unused = null;

  @Test
  public void testOakVerifier_verifyEvidence_successful() throws Exception {
    OakAttestationVerifier verifier = createVerifier();
    OakAttestationEvidence evidence = loadEvidence("manual_oak_attestation_evidence.textproto");
    PublicKey claimedPublicKey = loadPublicKeyFromCsr("certificate_signing_request.pem");
    ReferenceValues rv = getReferenceValues();

    boolean result = verifier.verify(evidence, claimedPublicKey, rv);
    assertThat(result).isTrue();
  }

  @Test
  public void testOakVerifier_verifyEvidence_invalidSignature_returnsEmpty() throws Exception {
    OakAttestationVerifier verifier = createVerifier();
    OakAttestationEvidence evidence = loadEvidence("manual_oak_attestation_evidence.textproto");
    // Use a random public key that doesn't match the one signed in the evidence
    KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");
    rsaKeyGen.initialize(4096);
    PublicKey wrongKey = rsaKeyGen.generateKeyPair().getPublic();
    ReferenceValues rv = getReferenceValues();

    boolean result = verifier.verify(evidence, wrongKey, rv);
    assertThat(result).isFalse();
  }

  @Test
  public void testOakVerifier_verifyEvidence_throwsOnWrongType() throws Exception {
    OakAttestationVerifier verifier = createVerifier();
    AttestationEvidence wrongEvidence = AwsAttestationEvidence.create(ByteString.EMPTY);
    ReferenceValues rv = getReferenceValues();

    assertThrows(ClassCastException.class, () -> verifier.verify(wrongEvidence, null, rv));
  }

  @Test
  public void testOakVerifier_verifyEvidence_successful_withRegex() throws Exception {
    OakAttestationVerifier verifier = createVerifier();
    OakAttestationEvidence evidence = loadEvidence("manual_oak_attestation_evidence.textproto");
    PublicKey claimedPublicKey = loadPublicKeyFromCsr("certificate_signing_request.pem");
    ReferenceValues rv = getReferenceValues("manual_oak_reference_values_regex.textproto");

    boolean result = verifier.verify(evidence, claimedPublicKey, rv);
    assertThat(result).isTrue();
  }

  @Test
  public void testOakVerifier_verifyEvidence_failed_withRegexMismatch() throws Exception {
    OakAttestationVerifier verifier = createVerifier();
    OakAttestationEvidence evidence = loadEvidence("manual_oak_attestation_evidence.textproto");
    PublicKey claimedPublicKey = loadPublicKeyFromCsr("certificate_signing_request.pem");
    ReferenceValues rv = getReferenceValues("manual_oak_reference_values_regex_mismatch.textproto");

    boolean result = verifier.verify(evidence, claimedPublicKey, rv);
    assertThat(result).isFalse();
  }

  private OakAttestationVerifier createVerifier() {
    return new OakAttestationVerifier(new OakEvidenceVerifier(), new DefaultTimeProvider());
  }

  private OakAttestationEvidence loadEvidence(String evidenceFilename) throws IOException {
    String evidenceText =
        new String(Files.readAllBytes(Paths.get(TEST_DATA_DIR + evidenceFilename)));
    com.google.tca.v1.OakAttestationEvidence.Builder protoBuilder =
        com.google.tca.v1.OakAttestationEvidence.newBuilder();
    TextFormat.Parser parser = TextFormat.Parser.newBuilder().setAllowUnknownFields(true).build();
    parser.merge(evidenceText, protoBuilder);
    com.google.tca.v1.OakAttestationEvidence protoEvidence = protoBuilder.build();

    return OakAttestationEvidence.create(
        protoEvidence.getEvidence(),
        protoEvidence.getEndorsements(),
        protoEvidence.getSignedPublicKey());
  }

  private PublicKey loadPublicKeyFromCsr(String filename) throws Exception {
    try (Reader reader = Files.newBufferedReader(Paths.get(TEST_DATA_DIR + filename));
        PEMParser pemParser = new PEMParser(reader)) {
      Object object = pemParser.readObject();
      if (object instanceof PKCS10CertificationRequest) {
        return new JcaPKCS10CertificationRequest((PKCS10CertificationRequest) object)
            .getPublicKey();
      }
      throw new IllegalArgumentException("File does not contain a valid CSR");
    }
  }

  private ReferenceValues getReferenceValues() throws IOException {
    return getReferenceValues("manual_oak_reference_values.textproto");
  }

  private ReferenceValues getReferenceValues(String filename) throws IOException {
    ByteString raw_rv = loadReferenceValues(filename).toByteString();
    return new ReferenceValues(ReferenceValuesType.OAK, raw_rv);
  }

  private com.google.oak.attestation.v1.ReferenceValues loadReferenceValues(String filename)
      throws IOException {
    String refValuesText = new String(Files.readAllBytes(Paths.get(TEST_DATA_DIR + filename)));
    com.google.oak.attestation.v1.ReferenceValues.Builder refValuesBuilder =
        com.google.oak.attestation.v1.ReferenceValues.newBuilder();
    TextFormat.Parser parser = TextFormat.Parser.newBuilder().setAllowUnknownFields(true).build();
    parser.merge(refValuesText, refValuesBuilder);
    return refValuesBuilder.build();
  }
}
