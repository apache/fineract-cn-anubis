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
package io.mifos.anubis.test.v1;

import io.mifos.anubis.api.v1.client.Anubis;
import io.mifos.anubis.api.v1.client.AnubisApiFactory;
import io.mifos.anubis.api.v1.domain.AllowedOperation;
import io.mifos.core.api.context.AutoSeshat;
import io.mifos.core.api.context.AutoUserContext;
import io.mifos.core.lang.AutoTenantContext;
import io.mifos.core.lang.TenantContextHolder;
import io.mifos.core.test.env.TestEnvironment;
import org.junit.rules.ExternalResource;

import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.function.BooleanSupplier;

import static io.mifos.core.test.env.TestEnvironment.SPRING_APPLICATION_NAME_PROPERTY;


/**
 * Needs to be initialized after the tenant context is set.
 *
 * @author Myrle Krantz
 */
@SuppressWarnings({"WeakerAccess", "unused"})
public class TenantApplicationSecurityEnvironmentTestRule extends ExternalResource {

  private final String applicationName;
  private final String applicationUri;

  private final SystemSecurityEnvironment systemSecurityEnvironment;
  private final BooleanSupplier waitForInitialize;

  public TenantApplicationSecurityEnvironmentTestRule(final TestEnvironment testEnvironment) {
    this(testEnvironment, () -> true);
  }

  public TenantApplicationSecurityEnvironmentTestRule(final TestEnvironment testEnvironment, final BooleanSupplier waitForInitialize)
  {
    this(testEnvironment.getProperty(SPRING_APPLICATION_NAME_PROPERTY),
            testEnvironment.serverURI(),
            new SystemSecurityEnvironment(
                    testEnvironment.getSeshatPublicKey(),
                    testEnvironment.getSeshatPrivateKey()),
            waitForInitialize);
  }

  public TenantApplicationSecurityEnvironmentTestRule(final String applicationName, final String applicationUri, final SystemSecurityEnvironment systemSecurityEnvironment) {
    this(applicationName, applicationUri, systemSecurityEnvironment, () -> true);
  }

  public TenantApplicationSecurityEnvironmentTestRule(final String applicationName, final String applicationUri, final SystemSecurityEnvironment systemSecurityEnvironment, final BooleanSupplier waitForInitialize)
  {
    this.applicationName = applicationName;
    this.applicationUri = applicationUri;
    this.systemSecurityEnvironment = systemSecurityEnvironment;
    this.waitForInitialize = waitForInitialize;
  }

  @Override
  protected void before(){
    initializeTenantInApplication();
    if (!waitForInitialize.getAsBoolean())
      throw new IllegalStateException("Initialize didn't complete.");
  }

  public void initializeTenantInApplication()
  {
    final Anubis anubis = AnubisApiFactory.create(applicationUri);

    final String seshatToken = systemSecurityEnvironment.seshatToken(applicationName);

    try (final AutoTenantContext x = new AutoTenantContext(TenantContextHolder.checkedGetIdentifier())) {
      try (final AutoSeshat y = new AutoSeshat(seshatToken)) {
        final RSAPublicKey publicKey = systemSecurityEnvironment.tenantPublicKey();
        anubis.initialize(publicKey.getModulus(), publicKey.getPublicExponent());
      }}
  }

  public SystemSecurityEnvironment getSystemSecurityEnvironment()
  {
    return systemSecurityEnvironment;
  }

  public AutoUserContext createAutoUserContext(final String userName)
  {
    return systemSecurityEnvironment.createAutoUserContext(userName, Collections.singletonList(applicationName));
  }

  public AutoUserContext createAutoSeshatContext()
  {
    return systemSecurityEnvironment.createAutoSeshatContext(applicationName);
  }

  public AutoUserContext createAutoSeshatContext(final String tenantName)
  {
    return systemSecurityEnvironment.createAutoSeshatContext(tenantName, applicationName);
  }

  public String getPermissionToken(
          final String userName,
          final String uri,
          final AllowedOperation allowedOperation) {
    return systemSecurityEnvironment.getPermissionToken(userName, applicationName, uri, allowedOperation);
  }

  public String seshatToken() {
    return systemSecurityEnvironment.seshatToken(applicationName);
  }
}
