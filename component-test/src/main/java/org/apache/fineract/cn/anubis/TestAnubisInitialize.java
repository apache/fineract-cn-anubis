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

import org.apache.fineract.cn.anubis.api.v1.client.Anubis;
import org.apache.fineract.cn.anubis.api.v1.client.AnubisApiFactory;
import org.apache.fineract.cn.anubis.api.v1.domain.AllowedOperation;
import org.apache.fineract.cn.anubis.api.v1.domain.Signature;
import org.apache.fineract.cn.anubis.test.v1.TenantApplicationSecurityEnvironmentTestRule;
import org.apache.fineract.cn.anubis.suites.SuiteTestEnvironment;
import org.apache.fineract.cn.api.context.AutoSeshat;
import org.apache.fineract.cn.api.context.AutoUserContext;
import org.apache.fineract.cn.api.util.InvalidTokenException;
import org.apache.fineract.cn.api.util.NotFoundException;
import org.apache.fineract.cn.lang.AutoTenantContext;
import org.apache.fineract.cn.test.fixture.TenantDataStoreTestContext;
import org.junit.Assert;
import org.junit.Test;

import java.security.interfaces.RSAPublicKey;

/**
 * @author Myrle Krantz
 */
public class TestAnubisInitialize extends AbstractSimpleTest {

  @Test
  public void testBrokenToken()
  {
    try (final TenantDataStoreTestContext ignored = TenantDataStoreTestContext.forRandomTenantName(SuiteTestEnvironment.cassandraInitializer)) {
      example.uninitialize(); //make sure the internal initialize variable isn't set before we start.

      final String brokenSeshatToken = "hmmmm, this doesn't look like a token?";

      try {

        final Anubis anubis = AnubisApiFactory.create(SuiteTestEnvironment.testEnvironment.serverURI(), logger);

        try (final AutoSeshat ignored2 = new AutoSeshat(brokenSeshatToken)) {
          final TenantApplicationSecurityEnvironmentTestRule securityMock = new TenantApplicationSecurityEnvironmentTestRule(
              SuiteTestEnvironment.testEnvironment);

          final String keyTimestamp = securityMock.getSystemSecurityEnvironment().tenantKeyTimestamp();
          final RSAPublicKey publicKey = securityMock.getSystemSecurityEnvironment().tenantPublicKey();
          final Signature signature = new Signature(publicKey.getModulus(), publicKey.getPublicExponent());

          anubis.createSignatureSet(keyTimestamp, signature);
        }

        Assert.fail("A call with a broken token should result in an exception thrown.");
      } catch (final InvalidTokenException e) {
        Assert.assertFalse("Service init code should not have been reached with a broken token.",
                example.initialized());
      }
    }
  }

  @Test
  public void testHappyCase() {
    try (final TenantDataStoreTestContext ignored = TenantDataStoreTestContext.forRandomTenantName(
        SuiteTestEnvironment.cassandraInitializer)) {
      initialize();
    }
  }

  @Test
  public void testReinitialize() {
    try (final TenantDataStoreTestContext ignored = TenantDataStoreTestContext.forRandomTenantName(
        SuiteTestEnvironment.cassandraInitializer)) {

      initialize();

      initialize();
    }
  }

  @Test
  public void testTwoTenants() {

    try (final TenantDataStoreTestContext ignored = TenantDataStoreTestContext.forRandomTenantName(
        SuiteTestEnvironment.cassandraInitializer)) {
      initialize();
    }

    try (final TenantDataStoreTestContext ignored = TenantDataStoreTestContext.forRandomTenantName(
        SuiteTestEnvironment.cassandraInitializer)) {
      initialize();
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testNoTenant() {
    try (final AutoTenantContext ignored = new AutoTenantContext("")) {
      initialize();
    }
  }

  @Test(expected = NotFoundException.class)
  public void testNonExistentTenant() {
    try (final AutoTenantContext ignored = new AutoTenantContext("monster_under_your_bed")) {
      initialize();
    }
  }

  @Test(expected = InvalidTokenException.class)
  public void testAuthenticateWithoutInitialize() {
    try (final TenantDataStoreTestContext ignored = TenantDataStoreTestContext.forRandomTenantName(
        SuiteTestEnvironment.cassandraInitializer)) {

      final TenantApplicationSecurityEnvironmentTestRule tenantApplicationSecurityEnvironment
              = new TenantApplicationSecurityEnvironmentTestRule(
          SuiteTestEnvironment.testEnvironment);
      final String permissionToken = tenantApplicationSecurityEnvironment.getPermissionToken("bubba", "foo", AllowedOperation.READ);
      try (final AutoUserContext ignored2 = new AutoUserContext("bubba", permissionToken)) {
        Assert.assertFalse(example.foo());
        Assert.fail("Not found exception should be thrown when authentication is attempted ");
      }
    }
  }

  private void initialize() {
    final TenantApplicationSecurityEnvironmentTestRule tenantApplicationSecurityEnvironment
            = new TenantApplicationSecurityEnvironmentTestRule(SuiteTestEnvironment.testEnvironment);
    tenantApplicationSecurityEnvironment.initializeTenantInApplication();

    try (final AutoUserContext ignored = tenantApplicationSecurityEnvironment.createAutoUserContext("x")) {
      Assert.assertTrue(example.initialized());
    }
  }

  //TODO: tests still needed for getting application key and deleting keysets.
}
