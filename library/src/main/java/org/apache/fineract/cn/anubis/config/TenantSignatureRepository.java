/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.fineract.cn.anubis.config;


import org.apache.fineract.cn.anubis.api.v1.domain.ApplicationSignatureSet;
import org.apache.fineract.cn.anubis.api.v1.domain.Signature;

import java.util.List;
import java.util.Optional;
import org.apache.fineract.cn.lang.security.RsaKeyPairFactory;

public interface TenantSignatureRepository {
  /**
   *
   * @param timestamp The timestamp of the signature to get.
   * @return The public keys that the identity service uses for signing tokens.
   * @throws IllegalArgumentException if the tenant context is not set.
   */
  Optional<Signature> getIdentityManagerSignature(String timestamp) throws IllegalArgumentException;

  List<String> getAllSignatureSetKeyTimestamps();

  Optional<ApplicationSignatureSet> getSignatureSet(String timestamp);

  Optional<ApplicationSignatureSet> getLatestSignatureSet();

  void deleteSignatureSet(String timestamp);

  Optional<Signature> getApplicationSignature(String timestamp);

  Optional<Signature> getLatestApplicationSignature();

  Optional<RsaKeyPairFactory.KeyPairHolder> getLatestApplicationSigningKeyPair();
}
