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
import org.apache.fineract.cn.anubis.test.v1.TenantApplicationSecurityEnvironmentTestRule;
import org.apache.fineract.cn.api.context.AutoGuest;
import org.apache.fineract.cn.api.context.AutoUserContext;
import org.apache.fineract.cn.api.util.NotFoundException;
import org.junit.Assert;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * @author Myrle Krantz
 */
public class TestSystemToken extends AbstractSimpleTest {
  @SuppressWarnings({"SpringAutowiredFieldsWarningInspection", "SpringJavaAutowiringInspection"})
  @Autowired
  private MetricsFeignClient metricsFeignClient;

  @Test
  public void shouldNotBeAbleToContactSpringEndpointWithGuestTokenWhenNotSoConfigured() throws Exception {
    try (final AutoUserContext ignored = new AutoGuest()) {
      metricsFeignClient.getMetrics();
      Assert.fail("Should not be able to get metrics with guest token unless system is so configured.");
    }
    catch (final NotFoundException ignore) { }

    try (final AutoUserContext ignored = tenantApplicationSecurityEnvironment.createAutoSeshatContext()) {
      final Metrics metrics = metricsFeignClient.getMetrics();
      Assert.assertTrue(metrics.getThreads() > 0);
    }
  }

  @Test
  public void shouldBeAbleToGetForForeignApplication() throws Exception {
    final TenantApplicationSecurityEnvironmentTestRule tenantForeignApplicationSecurityEnvironment
            = new TenantApplicationSecurityEnvironmentTestRule("foreign-v1", testEnvironment.serverURI(),
            new SystemSecurityEnvironment(testEnvironment.getSystemKeyTimestamp(), testEnvironment.getSystemPublicKey(), testEnvironment.getSystemPrivateKey()));
    try (final AutoUserContext ignored = tenantForeignApplicationSecurityEnvironment.createAutoSeshatContext()) {
      final boolean ret = example.forApplication("foreign-v1");
      Assert.assertTrue(ret);
    }
  }

  @Test(expected = NotFoundException.class)
  public void shouldNotBeAbleToGetForForeignApplicationWhenForeignApplicationNotEnabled() throws Exception {
    final TenantApplicationSecurityEnvironmentTestRule tenantForeignApplicationSecurityEnvironment
            = new TenantApplicationSecurityEnvironmentTestRule("foreign-v1", testEnvironment.serverURI(),
            new SystemSecurityEnvironment(testEnvironment.getSystemKeyTimestamp(), testEnvironment.getSystemPublicKey(), testEnvironment.getSystemPrivateKey()));
    try (final AutoUserContext ignored = tenantForeignApplicationSecurityEnvironment.createAutoSeshatContext()) {
      example.notForApplication("foreign-v1");
      Assert.fail("Shouldn't be able to access for a foreign token in this case.");
    }
  }
}