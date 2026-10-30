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

package com.google.tca.adapters;

import com.google.tca.domain.CertificateModifier;
import com.google.tca.domain.CertificateSigner;
import com.google.tca.domain.TimeProvider;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectKeyIdentifier;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

@Singleton
public class CertificateSignerImpl implements CertificateSigner {
  static {
    Security.addProvider(new BouncyCastleProvider());
  }

  private final TimeProvider timeProvider;

  @Inject
  public CertificateSignerImpl(TimeProvider timeProvider) {
    this.timeProvider = timeProvider;
  }

  @Override
  public X509Certificate signCsr(
      byte[] csrBytes,
      X509Certificate issuerCert,
      PrivateKey issuerPrivateKey,
      Instant notBefore,
      Instant notAfter,
      List<CertificateModifier> modifiers,
      X500Principal subject)
      throws CertificateException, IOException {
    try {
      PKCS10CertificationRequest csr = new PKCS10CertificationRequest(csrBytes);

      BigInteger serial = BigInteger.valueOf(timeProvider.now().toEpochMilli());

      X509v3CertificateBuilder certBuilder =
          new JcaX509v3CertificateBuilder(
              issuerCert.getSubjectX500Principal(),
              serial,
              Date.from(notBefore),
              Date.from(notAfter),
              subject,
              new JcaPEMKeyConverter().getPublicKey(csr.getSubjectPublicKeyInfo()));

      JcaX509ExtensionUtils extUtils = new JcaX509ExtensionUtils();
      AuthorityKeyIdentifier aki = createAuthorityKeyIdentifier(issuerCert);
      SubjectKeyIdentifier ski = extUtils.createSubjectKeyIdentifier(csr.getSubjectPublicKeyInfo());

      certBuilder.addExtension(Extension.authorityKeyIdentifier, false, aki);
      certBuilder.addExtension(Extension.subjectKeyIdentifier, false, ski);

      modifiers.forEach(modifier -> modifier.apply(certBuilder));

      ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerPrivateKey);

      return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    } catch (CertificateException e) {
      throw e;
    } catch (OperatorCreationException | GeneralSecurityException e) {
      throw new CertificateException(e);
    }
  }

  private AuthorityKeyIdentifier createAuthorityKeyIdentifier(X509Certificate issuerCert)
      throws CertificateException, IOException {
    byte[] skiExtValue = issuerCert.getExtensionValue(Extension.subjectKeyIdentifier.getId());
    if (skiExtValue == null) {
      throw new CertificateException(
          "Issuer certificate is missing Subject Key Identifier (SKI) extension");
    }
    // Populate only keyIdentifier (RFC 5280 Section 4.2.1.1) and omit authorityCertIssuer and
    // authorityCertSerialNumber. BouncyCastle's createAuthorityKeyIdentifier(X509Certificate)
    // embeds the issuer's serial and issuer DN, breaking X.509 path building across
    // cross-signed root certificates during CA key rotation.
    SubjectKeyIdentifier issuerSki =
        SubjectKeyIdentifier.getInstance(JcaX509ExtensionUtils.parseExtensionValue(skiExtValue));
    return new AuthorityKeyIdentifier(issuerSki.getKeyIdentifier());
  }
}
