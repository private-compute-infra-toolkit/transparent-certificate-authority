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

package com.google.tca.adapters.certsigning;

import com.google.tca.domain.CertificateModifier;
import com.google.tca.domain.CertificateModifiersCreator;
import com.google.tca.domain.policy.BasicConstraints;
import com.google.tca.domain.policy.NameConstraints;
import com.google.tca.domain.policy.Policy;
import jakarta.inject.Inject;
import jakarta.inject.Singleton;
import java.util.ArrayList;
import java.util.List;

@Singleton
public class CertificateModifiersCreatorImpl implements CertificateModifiersCreator {

  @Inject
  public CertificateModifiersCreatorImpl() {}

  @Override
  public List<CertificateModifier> create(Policy policy, String trustDomain) {
    List<CertificateModifier> modifiers = new ArrayList<>();

    if (policy.certificateAttributes().extensions().nameConstraints().isPresent()) {
      NameConstraints constraints =
          policy.certificateAttributes().extensions().nameConstraints().get();
      NameConstraintsModifier ncm =
          new NameConstraintsModifier(constraints.permittedSubtrees(), trustDomain);
      modifiers.add(ncm);
    }

    if (policy.certificateAttributes().extensions().basicConstraints().isPresent()) {
      BasicConstraints basicConstraints =
          policy.certificateAttributes().extensions().basicConstraints().get();
      modifiers.add(new BasicConstraintsModifier(basicConstraints));
      modifiers.add(new KeyUsageModifier(basicConstraints));
    }

    modifiers.add(new SubjectAlternativeNameModifier(policy, trustDomain));

    return modifiers;
  }
}
