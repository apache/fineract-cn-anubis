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
package org.apache.fineract.cn.anubis.security;

import com.google.gson.Gson;
import io.jsonwebtoken.*;
import org.apache.fineract.cn.anubis.annotation.AcceptedTokenType;
import org.apache.fineract.cn.anubis.api.v1.TokenConstants;
import org.apache.fineract.cn.anubis.api.v1.domain.AccountAccess;
import org.apache.fineract.cn.anubis.api.v1.domain.AccountAccessTokenContent;
import org.apache.fineract.cn.anubis.api.v1.domain.TokenContent;
import org.apache.fineract.cn.anubis.api.v1.domain.TokenPermission;
import org.apache.fineract.cn.anubis.provider.FinKeycloakRsaKeyProvider;
import org.apache.fineract.cn.anubis.service.PermittableService;
import org.apache.fineract.cn.lang.ApplicationName;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import javax.annotation.Nonnull;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.apache.fineract.cn.anubis.config.AnubisConstants.LOGGER_NAME;

/**
 * @author manoj
 */
@Component
public class FinKeycloakTenantAuthenticator {
 private final FinKeycloakRsaKeyProvider keycloakRsaKeyProvider;
 private final String applicationNameWithVersion;
 private final Gson gson;
 private final Set<ApplicationPermission> guestPermissions;
 private final Logger logger;

 @Autowired
 public FinKeycloakTenantAuthenticator(
         final FinKeycloakRsaKeyProvider keycloakRsaKeyProvider,
         final ApplicationName applicationName,
         final PermittableService permittableService,
         final @Qualifier("anubisGson") Gson gson,
         final @Qualifier(LOGGER_NAME) Logger logger) {
  this.keycloakRsaKeyProvider = keycloakRsaKeyProvider;
  this.applicationNameWithVersion = applicationName.toString();
  this.gson = gson;
  this.guestPermissions
          = permittableService.getPermittableEndpointsAsPermissions(AcceptedTokenType.GUEST);
  this.logger = logger;
 }

 AnubisAuthentication authenticate(
         final @Nonnull String user,
         final @Nonnull String token,
         final @Nonnull String keyTimestamp) {
  try {
   final JwtParser parser = Jwts.parser()
           .setSigningKey(keycloakRsaKeyProvider.getPublicKey());

   @SuppressWarnings("unchecked") Jwt<Header, Claims> jwt = parser.parse(token);

   final String serializedTokenContent = jwt.getBody().get("tokenPermissions", String.class);


   final String sourceApplication = "Keycloak";
   final TokenContent tokenContent = gson.fromJson(serializedTokenContent, TokenContent.class);
   if (tokenContent == null)
    throw AmitAuthenticationException.missingTokenContent();

   final Set<ApplicationPermission> permissions = translatePermissions(tokenContent.getTokenPermissions());
   permissions.addAll(guestPermissions);


   if(jwt.getBody().get("fin") != null){
    final String serializedAccountAccess =  jwt.getBody().get("fin", String.class);
    final AccountAccessTokenContent accountAccess = gson.fromJson(serializedAccountAccess, AccountAccessTokenContent.class);
    final Set<ApplicationPermission> acctPermissions = translateAccountPermissions(accountAccess.getAccounts());
    permissions.addAll(acctPermissions);
   }


   logger.info("Tenant token for user {}, with key timestamp {} authenticated successfully.", user, keyTimestamp);

   return new AnubisAuthentication(TokenConstants.PREFIX + token,
           jwt.getBody().get("preferred_username", String.class), applicationNameWithVersion, sourceApplication, permissions
   );
  }
  catch (final JwtException | InvalidKeySpecException | NoSuchAlgorithmException e) {
   logger.info("Tenant token for user {}, with key timestamp {} failed to authenticate. Exception was {}", user, keyTimestamp, e);
   throw AmitAuthenticationException.invalidToken();
  }
 }

 private Set<ApplicationPermission> translatePermissions(
         @Nonnull final List<TokenPermission> tokenPermissions)
 {
  return tokenPermissions.stream()
          .filter(x -> x.getPath().startsWith(applicationNameWithVersion))
          .flatMap(this::getAppPermissionFromTokenPermission)
          .collect(Collectors.toSet());
 }

 private Set<ApplicationPermission> translateAccountPermissions(
         @Nonnull final List<AccountAccess> tokenPermissions)
 {
  return tokenPermissions.stream()
          .flatMap(this::getAppPermissionFromAcctPermission)
          .collect(Collectors.toSet());
 }

 private Stream<ApplicationPermission> getAppPermissionFromTokenPermission(final TokenPermission tokenPermission) {
  final String servletPath = tokenPermission.getPath().substring(applicationNameWithVersion.length());
  return tokenPermission.getAllowedOperations().stream().map(x -> new ApplicationPermission(servletPath, x, false));
 }

 private Stream<ApplicationPermission> getAppPermissionFromAcctPermission(final AccountAccess tokenPermission) {
  final String servletPath = "ACCT_ACCESS_"+ tokenPermission.getNumber();
  return tokenPermission.getAccess().stream().map(x -> new ApplicationPermission(servletPath, x, false));
 }
}
