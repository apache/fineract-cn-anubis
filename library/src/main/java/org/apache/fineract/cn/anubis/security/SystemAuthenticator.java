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

import static org.apache.fineract.cn.anubis.config.AnubisConstants.LOGGER_NAME;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import java.util.Set;
import org.apache.fineract.cn.anubis.annotation.AcceptedTokenType;
import org.apache.fineract.cn.anubis.api.v1.TokenConstants;
import org.apache.fineract.cn.anubis.provider.InvalidKeyTimestampException;
import org.apache.fineract.cn.anubis.provider.SystemRsaKeyProvider;
import org.apache.fineract.cn.anubis.service.PermittableService;
import org.apache.fineract.cn.anubis.token.TokenType;
import org.apache.fineract.cn.api.util.ApiConstants;
import org.apache.fineract.cn.lang.TenantContextHolder;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

/**
 * @author Myrle Krantz
 */
@Component
public class SystemAuthenticator {
  private final SystemRsaKeyProvider systemRsaKeyProvider;
  private final Set<ApplicationPermission> permissions;
  private final Logger logger;

  @Autowired
  public SystemAuthenticator(
          final SystemRsaKeyProvider systemRsaKeyProvider,
          final PermittableService permittableService,
          final @Qualifier(LOGGER_NAME) Logger logger) {
    this.systemRsaKeyProvider = systemRsaKeyProvider;
    this.permissions = permittableService.getPermittableEndpointsAsPermissions(AcceptedTokenType.SYSTEM);
    this.logger = logger;
  }

  @SuppressWarnings("WeakerAccess")
  public AnubisAuthentication authenticate(
      final String user,
      final String token,
      final String keyTimestamp) {
    if (!user.equals(ApiConstants.SYSTEM_SU))
      throw AmitAuthenticationException.invalidHeader();

    try {
      final JwtParser jwtParser = Jwts.parser()
          .setSigningKey(systemRsaKeyProvider.getPublicKey(keyTimestamp))
          .requireIssuer(TokenType.SYSTEM.getIssuer())
          .require(TokenConstants.JWT_SIGNATURE_TIMESTAMP_CLAIM, keyTimestamp);

      TenantContextHolder.identifier().ifPresent(jwtParser::requireSubject);

      //noinspection unchecked
      final Jwt<Header, Claims> result = jwtParser.parse(token);
      if (result.getBody() == null ||
              result.getBody().getAudience() == null) {
        logger.info("System token for user {}, with key timestamp {} failed to authenticate. Audience was not set.", user, keyTimestamp);
        throw AmitAuthenticationException.invalidToken();
      }

      logger.info("System token for user {}, with key timestamp {} authenticated successfully.", user, keyTimestamp);

      return new AnubisAuthentication(
              TokenConstants.PREFIX + token,
              user,
              result.getBody().getAudience(),
              TokenType.SYSTEM.getIssuer(),
              permissions);
    }
    catch (final JwtException e) {
      logger.debug("token = {}", token);
      logger.info("System token for user {}, with key timestamp {} failed to authenticate. Exception was {}", user, keyTimestamp, e.getMessage());
      throw AmitAuthenticationException.invalidToken();
    } catch (final InvalidKeyTimestampException e) {
      logger.info("System token for user {}, with key timestamp {} failed to authenticate. Exception was {}", user, keyTimestamp, e.getMessage());
      throw AmitAuthenticationException.invalidTokenKeyTimestamp("system", keyTimestamp);
    }
  }
}
