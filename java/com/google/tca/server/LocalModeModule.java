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

package com.google.tca.server;

import com.google.inject.AbstractModule;
import com.google.mbs.MbsCertificateFactory;
import com.google.mbs.MeasurementBoundCertificate;
import com.google.mbs.attestationcollection.AttestationToken;
import com.google.mbs.qualifier.MbsRoot;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Optional;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

/** Guice module for TCA local mode. */
public class LocalModeModule extends AbstractModule {

  static {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  private final LocalArgs args;

  public LocalModeModule(LocalArgs args) {
    this.args = args;
  }

  @Override
  protected void configure() {
    bind(AwsInstanceMetadata.class)
        .toInstance(
            AwsInstanceMetadata.builder()
                .setRegion("local")
                .setAccountId("dummy_account")
                .setEnvironment("local")
                .setDomain("pcit.goog")
                .build());

    MbsCertificateFactory.X509CertificateAndPrivateKey certAndKey =
        MbsCertificateFactory.createSelfSignedCertificatesFactory(
                new MbsCertificateFactory.CertSignatureSpec("RSA", 4096, "SHA256withRSA"),
                new X500Name("CN=TCA Local"),
                Duration.ofDays(180),
                Optional.of(
                    new GeneralNames(
                        new GeneralName(
                            GeneralName.uniformResourceIdentifier, "spiffe://tca.local.test"))),
                KeyUsage.keyCertSign)
            .generate();

    MeasurementBoundCertificate cert =
        new MeasurementBoundCertificate(
            certAndKey.certificate(),
            certAndKey.privateKey(),
            AttestationToken.fromBytes("DummyToken".getBytes()));

    bind(MeasurementBoundCertificate.class).toInstance(cert);
    bind(X509Certificate.class).annotatedWith(MbsRoot.class).toInstance(cert.getCertificate());
    bind(PrivateKey.class).annotatedWith(MbsRoot.class).toInstance(cert.getPrivateKey());
  }
}
