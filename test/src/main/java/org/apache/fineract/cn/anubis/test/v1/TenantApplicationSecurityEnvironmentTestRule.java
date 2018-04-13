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
package org.apache.fineract.cn.anubis.test.v1;

import static org.apache.fineract.cn.test.env.TestEnvironment.SPRING_APPLICATION_NAME_PROPERTY;

import org.apache.fineract.cn.anubis.api.v1.client.Anubis;
import org.apache.fineract.cn.anubis.api.v1.client.AnubisApiFactory;
import org.apache.fineract.cn.anubis.api.v1.domain.AllowedOperation;
import org.apache.fineract.cn.anubis.api.v1.domain.ApplicationSignatureSet;
import org.apache.fineract.cn.anubis.api.v1.domain.Signature;
import org.apache.fineract.cn.api.context.AutoSeshat;
import org.apache.fineract.cn.api.context.AutoUserContext;
import org.apache.fineract.cn.lang.AutoTenantContext;
import org.apache.fineract.cn.lang.TenantContextHolder;
import org.apache.fineract.cn.test.env.TestEnvironment;
import org.junit.rules.ExternalResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.function.BooleanSupplier;


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
  private final Logger logger;

  public TenantApplicationSecurityEnvironmentTestRule(final TestEnvironment testEnvironment) {
    this(testEnvironment, () -> true);
  }

  public TenantApplicationSecurityEnvironmentTestRule(final TestEnvironment testEnvironment, final BooleanSupplier waitForInitialize)
  {
    this(testEnvironment.getProperty(SPRING_APPLICATION_NAME_PROPERTY),
            testEnvironment.serverURI(),
            new SystemSecurityEnvironment(
                    testEnvironment.getSystemKeyTimestamp(),
                    testEnvironment.getSystemPublicKey(),
                    testEnvironment.getSystemPrivateKey()),
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
    this.logger = LoggerFactory.getLogger(SystemSecurityEnvironment.LOGGER_NAME);
  }

  @Override
  protected void before(){
    initializeTenantInApplication();
    if (!waitForInitialize.getAsBoolean())
      throw new IllegalStateException("Initialize didn't complete.");
  }

  public ApplicationSignatureSet initializeTenantInApplication()
  {
    final Anubis anubis = getAnubis();

    final String systemToken = systemSecurityEnvironment.systemToken(applicationName);

    try (final AutoTenantContext x = new AutoTenantContext(TenantContextHolder.checkedGetIdentifier())) {
      try (final AutoSeshat y = new AutoSeshat(systemToken)) {
        final String keyTimestamp = systemSecurityEnvironment.tenantKeyTimestamp();
        final RSAPublicKey publicKey = systemSecurityEnvironment.tenantPublicKey();
        final Signature identityManagerSignature = new Signature(publicKey.getModulus(), publicKey.getPublicExponent());
        final ApplicationSignatureSet resultingSignatureSet
            = anubis.createSignatureSet(keyTimestamp, identityManagerSignature);
        anubis.initializeResources();
        return resultingSignatureSet;
      }}
  }

  public Anubis getAnubis() {
    return AnubisApiFactory.create(applicationUri, logger);
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
    return systemSecurityEnvironment.createAutoSystemContext(applicationName);
  }

  public AutoUserContext createAutoSeshatContext(final String tenantName)
  {
    return systemSecurityEnvironment.createAutoSystemContext(tenantName, applicationName);
  }

  public String getPermissionToken(
          final String userName,
          final String uri,
          final AllowedOperation allowedOperation) {
    return systemSecurityEnvironment.getPermissionToken(userName, applicationName, uri, allowedOperation);
  }

  public String systemToken() {
    return systemSecurityEnvironment.systemToken(applicationName);
  }
}
