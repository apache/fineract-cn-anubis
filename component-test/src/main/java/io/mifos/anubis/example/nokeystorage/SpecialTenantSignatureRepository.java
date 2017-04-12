/*
 * Copyright 2017 The Mifos Initiative.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.mifos.anubis.example.nokeystorage;

import io.mifos.anubis.api.v1.domain.ApplicationSignatureSet;
import io.mifos.anubis.api.v1.domain.Signature;
import io.mifos.anubis.config.TenantSignatureRepository;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * @author Myrle Krantz
 */
@Component
public class SpecialTenantSignatureRepository implements TenantSignatureRepository {
  private final Map<String, ApplicationSignatureSet> applicationSignatureSetMap = new HashMap<>();

  void addSignatureSet(final ApplicationSignatureSet applicationSignatureSet) {
    applicationSignatureSetMap.put(applicationSignatureSet.getTimestamp(), applicationSignatureSet);
  }

  @Override
  public Optional<Signature> getIdentityManagerSignature(final String timestamp) throws IllegalArgumentException {
    final Optional<ApplicationSignatureSet> sigset = Optional.ofNullable(applicationSignatureSetMap.get(timestamp));
    return sigset.map(ApplicationSignatureSet::getIdentityManagerSignature);
  }

  @Override
  public List<String> getAllSignatureSetKeyTimestamps() {
    return applicationSignatureSetMap.keySet().stream().collect(Collectors.toList());
  }

  @Override
  public Optional<ApplicationSignatureSet> getSignatureSet(final String timestamp) {
    return Optional.ofNullable(applicationSignatureSetMap.get(timestamp));
  }

  @Override
  public void deleteSignatureSet(final String timestamp) {
    applicationSignatureSetMap.remove(timestamp);
  }

  @Override
  public Optional<Signature> getApplicationSignature(final String timestamp) {
    final Optional<ApplicationSignatureSet> sigset = Optional.ofNullable(applicationSignatureSetMap.get(timestamp));
    return sigset.map(ApplicationSignatureSet::getApplicationSignature);
  }

  @Override
  public Optional<ApplicationSignatureSet> getLatestSignatureSet() {
    Optional<String> timestamp = getMostRecentTimestamp();
    return timestamp.flatMap(this::getSignatureSet);
  }

  @Override
  public Optional<Signature> getLatestApplicationSignature() {
    Optional<String> timestamp = getMostRecentTimestamp();
    return timestamp.flatMap(this::getApplicationSignature);
  }

  private Optional<String> getMostRecentTimestamp() {
    return getAllSignatureSetKeyTimestamps().stream()
            .max(String::compareTo);
  }
}
