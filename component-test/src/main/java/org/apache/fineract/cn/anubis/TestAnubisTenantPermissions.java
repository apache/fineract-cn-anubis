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

import org.apache.fineract.cn.anubis.api.v1.domain.AllowedOperation;
import org.apache.fineract.cn.anubis.example.noinitialize.UserContext;
import org.apache.fineract.cn.anubis.test.v1.TenantApplicationSecurityEnvironmentTestRule;
import org.apache.fineract.cn.api.context.AutoSeshat;
import org.apache.fineract.cn.api.context.AutoUserContext;
import org.apache.fineract.cn.api.util.InvalidTokenException;
import org.apache.fineract.cn.api.util.NotFoundException;
import org.apache.fineract.cn.lang.AutoTenantContext;
import org.apache.fineract.cn.test.env.TestEnvironment;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;

/**
 * @author Myrle Krantz
 */
public class TestAnubisTenantPermissions extends AbstractNoInitializeTest {
  private static final String DUMMY_URI = "/dummy";
  private static final String DESIGNATOR_URI = "/parameterized/{useridentifier}/with/*/parameters";
  private static final String USER_NAME = "Meryre";

  @Rule
  public final TenantApplicationSecurityEnvironmentTestRule tenantApplicationSecurityEnvironment = new TenantApplicationSecurityEnvironmentTestRule(testEnvironment);

  @Test
  public void readPermissionShouldWorkToRead()
  {
    try (final AutoUserContext ignored = setPermissionContext(DUMMY_URI, AllowedOperation.READ))
    {
      example.getDummy();
    }
  }

  @Test(expected = NotFoundException.class)
  public void readPermissionShouldNotWorkToWrite()
  {
    try (final AutoUserContext ignored = setPermissionContext(DUMMY_URI, AllowedOperation.READ))
    {
      example.createDummy();
    }
  }

  @Test(expected = NotFoundException.class)
  public void readPermissionShouldNotWorkToDelete()
  {
    try (final AutoUserContext ignored = setPermissionContext(DUMMY_URI, AllowedOperation.READ))
    {
      example.deleteDummy();
    }
  }

  @Test
  public void changePermissionShouldWorkToWrite()
  {
    try (final AutoUserContext ignored = setPermissionContext(DUMMY_URI, AllowedOperation.CHANGE))
    {
      example.createDummy();
    }
  }

  @Test(expected = NotFoundException.class)
  public void changePermissionShouldNotWorkToRead()
  {
    try (final AutoUserContext ignored = setPermissionContext(DUMMY_URI, AllowedOperation.CHANGE))
    {
      example.getDummy();
    }
  }

  @Test(expected = NotFoundException.class)
  public void changePermissionShouldNotWorkToDelete()
  {
    try (final AutoUserContext ignored = setPermissionContext(DUMMY_URI, AllowedOperation.CHANGE))
    {
      example.deleteDummy();
    }
  }

  @Test
  public void deletePermissionShouldWorkToDelete()
  {
    try (final AutoUserContext ignored = setPermissionContext(DUMMY_URI, AllowedOperation.DELETE))
    {
      example.deleteDummy();
    }
  }

  @Test(expected = NotFoundException.class)
  public void deletePermissionShouldNotWorkToRead()
  {
    try (final AutoUserContext ignored = setPermissionContext(DUMMY_URI, AllowedOperation.DELETE))
    {
      example.getDummy();
    }
  }

  @Test(expected = NotFoundException.class)
  public void deletePermissionShouldNotWorkToChange()
  {
    try (final AutoUserContext ignored = setPermissionContext(DUMMY_URI, AllowedOperation.DELETE))
    {
      example.createDummy();
    }
  }

  @Test(expected = InvalidTokenException.class)
  public void tokenForWrongTenantShouldNotWork()
  {
    final String permissionToken;
    try (final AutoTenantContext ignored = TestEnvironment.createRandomTenantContext()) {
      permissionToken = tenantApplicationSecurityEnvironment.getPermissionToken(USER_NAME, DUMMY_URI, AllowedOperation.READ);
    }

    try (final AutoUserContext ignored = new AutoUserContext(USER_NAME, permissionToken))
    {
      example.getDummy();
    }
  }

  @Test(expected = InvalidTokenException.class)
  public void expiredTokenShouldNotWork() throws InterruptedException {
    final String permissionToken;
    try (final AutoTenantContext ignored = TestEnvironment.createRandomTenantContext()) {
      permissionToken = tenantApplicationSecurityEnvironment.getPermissionToken(USER_NAME, DUMMY_URI, AllowedOperation.READ);
    }

    Thread.sleep(150);

    try (final AutoUserContext ignored = new AutoUserContext(USER_NAME, permissionToken))
    {
      example.getDummy();
    }
  }

  @Test(expected = InvalidTokenException.class)
  public void tokenForWrongUserShouldNotWork() throws InterruptedException {
    final String permissionToken = tenantApplicationSecurityEnvironment.getPermissionToken(USER_NAME, DUMMY_URI, AllowedOperation.READ);

    try (final AutoUserContext ignored = new AutoUserContext("Menna", permissionToken))
    {
      example.getDummy();
    }
  }

  @Test(expected = NotFoundException.class)
  public void requestForAnotherUsersInformationWhenYoureOnlyPermittedToAccessOwnShouldNotWork()
  {
    try (final AutoUserContext ignored = setPermissionContext(DESIGNATOR_URI, AllowedOperation.READ))
    {
      example.parameterized("wrong_user_name", "silly_parameter");
    }
  }

  @Test
  public void requestYourOwnInformationWhenYoureOnlyPermittedToAccessOwnShouldWork()
  {
    try (final AutoUserContext ignored = setPermissionContext(DESIGNATOR_URI, AllowedOperation.READ))
    {
      final String ret = example.parameterized(USER_NAME, "silly_parameter");
      Assert.assertEquals(ret, USER_NAME+"silly_parameter"+42);
    }
  }

  @Test
  public void tenantTokenForSystemEndpointShouldNotWorkRegardlessOfPermissions()
  {
    try (final AutoSeshat ignored = new AutoSeshat(tenantApplicationSecurityEnvironment.systemToken()))
    {
      example.callSystemEndpoint();
    }
    catch (final InvalidTokenException e)
    {
      Assert.fail("call to system endpoint with system token should succeed.");
    }

    try (final AutoUserContext ignored = setPermissionContext("/systemendpoint", AllowedOperation.CHANGE))
    {
      example.callSystemEndpoint();
    }
  }

  @Test
  public void userNameShouldBeCorrectlySetInUserContext()
  {
    try (final AutoUserContext ignored = setPermissionContext("/usercontext", AllowedOperation.READ))
    {
      final UserContext context = example.getUserContext();
      Assert.assertEquals(USER_NAME, context.getUserIdentifier());
    }
  }

  private AutoUserContext setPermissionContext(final String uri, final AllowedOperation allowedOperation)
  {
    final String permissionToken = tenantApplicationSecurityEnvironment.getPermissionToken(USER_NAME, uri, allowedOperation);

    return new AutoUserContext(USER_NAME, permissionToken);
  }
}
