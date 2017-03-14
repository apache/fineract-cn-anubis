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

import io.mifos.anubis.api.v1.client.Anubis;
import io.mifos.anubis.api.v1.client.AnubisApiFactory;
import io.mifos.anubis.api.v1.client.TenantNotFoundException;
import io.mifos.anubis.example.simple.Example;
import io.mifos.anubis.example.simple.ExampleConfiguration;
import io.mifos.anubis.test.v1.TenantApplicationSecurityEnvironmentTestRule;
import io.mifos.core.api.context.AutoSeshat;
import io.mifos.core.api.context.AutoUserContext;
import io.mifos.core.api.util.InvalidTokenException;
import io.mifos.core.lang.AutoTenantContext;
import io.mifos.core.test.env.TestEnvironment;
import io.mifos.core.test.fixture.TenantDataStoreTestContext;
import io.mifos.core.test.fixture.cassandra.CassandraInitializer;
import org.junit.Assert;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.netflix.feign.EnableFeignClients;
import org.springframework.cloud.netflix.ribbon.RibbonClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.junit4.SpringRunner;

import java.security.interfaces.RSAPublicKey;

/**
 * @author Myrle Krantz
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
public class TestAnubisInitialize {
  private static final String APP_NAME = "anubis-v1";

  @Configuration
  @EnableFeignClients(basePackages = {"io.mifos.anubis.example.simple"})
  @RibbonClient(name = APP_NAME)
  @Import({ExampleConfiguration.class})
  public static class TestConfiguration {
    public TestConfiguration() {
      super();
    }

    @Bean()
    public Logger logger() {
      return LoggerFactory.getLogger(APP_NAME + "-logger");
    }
  }

  @ClassRule
  public static TestEnvironment testEnvironment = new TestEnvironment(APP_NAME);

  @ClassRule
  public static CassandraInitializer cassandraInitializer = new CassandraInitializer();

  @SuppressWarnings({"SpringAutowiredFieldsWarningInspection", "SpringJavaAutowiringInspection", "SpringJavaAutowiredMembersInspection"})
  @Autowired
  Example example;

  @Test
  public void testBrokenToken()
  {
    try (final TenantDataStoreTestContext ignored = TenantDataStoreTestContext.forRandomTenantName(cassandraInitializer)) {
      example.uninitialize(); //make sure the internal initialize variable isn't set before we start.

      final String brokenSeshatToken = "hmmmm, this doesn't look like a token?";

      try {

        final Anubis anubis = AnubisApiFactory.create(testEnvironment.serverURI());

        try (final AutoSeshat ignored2 = new AutoSeshat(brokenSeshatToken)) {
          final TenantApplicationSecurityEnvironmentTestRule securityMock = new TenantApplicationSecurityEnvironmentTestRule(testEnvironment);
          final RSAPublicKey publicKey = securityMock.getSystemSecurityEnvironment().tenantPublicKey();
          anubis.initialize(publicKey.getModulus(), publicKey.getPublicExponent());
        }

        Assert.assertFalse("A call with a broken token should result in an exception thrown.", true);
      } catch (final InvalidTokenException e) {
        Assert.assertFalse("Service init code should not have been reached with a broken token.",
                example.initialized());
      }
    }
  }

  @Test
  public void testHappyCase() {
    try (final TenantDataStoreTestContext ignored = TenantDataStoreTestContext.forRandomTenantName(cassandraInitializer)) {
      initialize();
    }
  }

  @Test
  public void testReinitialize() {
    try (final TenantDataStoreTestContext ignored = TenantDataStoreTestContext.forRandomTenantName(cassandraInitializer)) {

      initialize();

      initialize();
    }
  }

  @Test
  public void testTwoTenants() {

    try (final TenantDataStoreTestContext ignored = TenantDataStoreTestContext.forRandomTenantName(cassandraInitializer)) {
      initialize();
    }

    try (final TenantDataStoreTestContext ignored = TenantDataStoreTestContext.forRandomTenantName(cassandraInitializer)) {
      initialize();
    }
  }

  @Test(expected = IllegalArgumentException.class)
  public void testNoTenant() {
    try (final AutoTenantContext ignored = new AutoTenantContext("")) {
      initialize();
    }
  }

  @Test(expected = TenantNotFoundException.class)
  public void testNonExistentTenant() {
    try (final AutoTenantContext ignored = new AutoTenantContext("monster_under_your_bed")) {
      initialize();
    }
  }

  private void initialize() {
    final TenantApplicationSecurityEnvironmentTestRule tenantApplicationSecurityEnvironment
            = new TenantApplicationSecurityEnvironmentTestRule(testEnvironment);
    tenantApplicationSecurityEnvironment.initializeTenantInApplication();

    try (final AutoUserContext ignored = tenantApplicationSecurityEnvironment.createAutoUserContext("x")) {
      Assert.assertTrue(example.initialized());
    }
  }
}
