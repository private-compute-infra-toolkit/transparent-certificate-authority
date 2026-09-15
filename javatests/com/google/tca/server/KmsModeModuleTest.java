/*
 * Copyright 2026 Google LLC
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

package com.google.tca.server;

import static com.google.common.truth.Truth.assertThat;

import com.google.mbs.MbsCertificateFactory;
import java.security.cert.X509Certificate;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class KmsModeModuleTest {

  @Test
  public void provideMbsCertificateFactory_generatesCertificateWithCorrectSpiffeIdInSan()
      throws Exception {
    // 1. Setup module with test metadata
    String testEnv = "testenv";
    String testDomain = "testdomain";
    AwsInstanceMetadata awsInstanceMetadata =
        AwsInstanceMetadata.builder()
            .setRegion("us-east-1")
            .setAccountId("123456789012")
            .setEnvironment(testEnv)
            .setDomain(testDomain)
            .setInstanceId("i-0123456789abcdef0")
            .build();
    KmsArgs kmsArgs = new KmsArgs();
    KmsModeModule module = new KmsModeModule(kmsArgs, awsInstanceMetadata);

    // 2. Get the certificate factory & generate certificate
    MbsCertificateFactory factory = module.provideMbsCertificateFactory();
    X509Certificate rootCert = factory.generate().certificate();

    // 3. Verify subject principal
    assertThat(rootCert.getSubjectX500Principal().getName())
        .isEqualTo("CN=TCA Root,O=Google LLC,C=US");

    // 4. Verify the constructed SPIFFE ID in the SAN extension
    String expectedSpiffeId =
        "spiffe://tca.testenv.testdomain/operator/pcit.goog/123456789012/publisher/google.com/pcit-release-bot/workload/transparent-certificate-authority";

    byte[] sanExtensionValue = rootCert.getExtensionValue(Extension.subjectAlternativeName.getId());
    assertThat(sanExtensionValue).isNotNull();

    GeneralNames names =
        GeneralNames.getInstance(ASN1OctetString.getInstance(sanExtensionValue).getOctets());
    assertThat(names.getNames()).hasLength(1);

    GeneralName sanEntry = names.getNames()[0];
    assertThat(sanEntry.getTagNo()).isEqualTo(GeneralName.uniformResourceIdentifier);
    assertThat(sanEntry.getName().toString()).isEqualTo(expectedSpiffeId);
  }

  @Test
  public void provideMbsCertificateFactory_prodEnv_stripsAwsSubdomainAndOmitEnv() throws Exception {
    // 1. Setup module with prod metadata and "aws." subdomain
    String testEnv = "prod";
    String testDomain = "aws.pcit.goog";
    AwsInstanceMetadata awsInstanceMetadata =
        AwsInstanceMetadata.builder()
            .setRegion("us-east-1")
            .setAccountId("123456789012")
            .setEnvironment(testEnv)
            .setDomain(testDomain)
            .setInstanceId("i-0123456789abcdef0")
            .build();
    KmsArgs kmsArgs = new KmsArgs();
    KmsModeModule module = new KmsModeModule(kmsArgs, awsInstanceMetadata);

    // 2. Get the certificate factory & generate certificate
    MbsCertificateFactory factory = module.provideMbsCertificateFactory();
    X509Certificate rootCert = factory.generate().certificate();

    // 3. Verify subject principal
    assertThat(rootCert.getSubjectX500Principal().getName())
        .isEqualTo("CN=TCA Root,O=Google LLC,C=US");

    // 4. Verify the constructed SPIFFE ID in the SAN extension (should be tca.pcit.goog)
    String expectedSpiffeId =
        "spiffe://tca.pcit.goog/operator/pcit.goog/123456789012/publisher/google.com/pcit-release-bot/workload/transparent-certificate-authority";

    byte[] sanExtensionValue = rootCert.getExtensionValue(Extension.subjectAlternativeName.getId());
    assertThat(sanExtensionValue).isNotNull();

    GeneralNames names =
        GeneralNames.getInstance(ASN1OctetString.getInstance(sanExtensionValue).getOctets());
    assertThat(names.getNames()).hasLength(1);

    GeneralName sanEntry = names.getNames()[0];
    assertThat(sanEntry.getTagNo()).isEqualTo(GeneralName.uniformResourceIdentifier);
    assertThat(sanEntry.getName().toString()).isEqualTo(expectedSpiffeId);
  }

  @Test
  public void provideInstanceId_returnsConfiguredInstanceId() {
    String testInstanceId = "i-0123456789abcdef0";
    AwsInstanceMetadata awsInstanceMetadata =
        AwsInstanceMetadata.builder()
            .setRegion("us-east-1")
            .setAccountId("123456789012")
            .setEnvironment("test")
            .setDomain("pcit.goog")
            .setInstanceId(testInstanceId)
            .build();
    KmsArgs kmsArgs = new KmsArgs();
    KmsModeModule module = new KmsModeModule(kmsArgs, awsInstanceMetadata);

    assertThat(module.provideInstanceId()).isEqualTo(testInstanceId);
  }
}
