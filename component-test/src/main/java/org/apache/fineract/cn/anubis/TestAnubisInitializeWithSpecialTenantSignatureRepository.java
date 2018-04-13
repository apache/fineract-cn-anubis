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
package org.apache.fineract.cn.anubis;

import org.apache.fineract.cn.anubis.example.simple.Metrics;
import org.apache.fineract.cn.anubis.example.simple.MetricsFeignClient;
import org.apache.fineract.cn.anubis.test.v1.SystemSecurityEnvironment;
import org.apache.fineract.cn.api.context.AutoGuest;
import org.apache.fineract.cn.api.context.AutoSeshat;
import org.apache.fineract.cn.api.context.AutoUserContext;
import org.apache.fineract.cn.lang.AutoTenantContext;
import org.apache.fineract.cn.lang.TenantContextHolder;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @author Myrle Krantz
 */
public class TestAnubisInitializeWithSpecialTenantSignatureRepository extends AbstractNoKeyStorageTest {
  @SuppressWarnings({"SpringAutowiredFieldsWarningInspection", "SpringJavaAutowiringInspection"})
  @Autowired
  private MetricsFeignClient metricsFeignClient;

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

  @Test
  public void shouldBeAbleToContactSpringEndpointWithGuestTokenWhenSoConfigured() throws Exception {
    try (final AutoUserContext ignored = new AutoGuest()) {
      final Metrics metrics = metricsFeignClient.getMetrics();
      Assert.assertTrue(metrics.getThreads() > 0);
    }
  }
}
