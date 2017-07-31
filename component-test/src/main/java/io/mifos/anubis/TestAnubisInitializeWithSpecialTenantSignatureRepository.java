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
package io.mifos.anubis;

import io.mifos.anubis.test.v1.SystemSecurityEnvironment;
import io.mifos.core.api.context.AutoSeshat;
import io.mifos.core.lang.AutoTenantContext;
import io.mifos.core.lang.TenantContextHolder;
import org.junit.Test;

/**
 * @author Myrle Krantz
 */
public class TestAnubisInitializeWithSpecialTenantSignatureRepository extends AbstractNoKeyStorageTest {
  @Test
  public void test()
  {
    final SystemSecurityEnvironment systemSecurityEnvironment = new SystemSecurityEnvironment(
            testEnvironment.getSystemKeyTimestamp(),
            testEnvironment.getSystemPublicKey(),
            testEnvironment.getSystemPrivateKey());

    final String systemToken = systemSecurityEnvironment.systemToken(APP_NAME);

    try (final AutoTenantContext ignored = new AutoTenantContext(TenantContextHolder.checkedGetIdentifier())) {
      try (final AutoSeshat ignored2 = new AutoSeshat(systemToken)) {
        example.initialize();
      }}
  }
}
