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
package io.mifos.anubis.token;

import io.mifos.anubis.api.v1.TokenConstants;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;


/**
 * @author Myrle Krantz
 */
@SuppressWarnings({"WeakerAccess", "unused"})
@Component
public class SystemAccessTokenSerializer {

  public static class Specification {
    private PrivateKey privateKey;
    private String tenant;
    private String role;
    private long secondsToLive;
    private String targetApplicationName;

    public Specification setPrivateKey(final PrivateKey privateKey) {
      this.privateKey = privateKey;
      return this;
    }

    public Specification setTenant(final String tenant) {
      this.tenant = tenant;
      return this;
    }

    public Specification setRole(final String role) {
      this.role = role;
      return this;
    }

    public Specification setSecondsToLive(final long secondsToLive) {
      this.secondsToLive = secondsToLive;
      return this;
    }

    public Specification setTargetApplicationName(final String targetApplicationName)
    {
      this.targetApplicationName = targetApplicationName;
      return this;
    }
  }

  public TokenSerializationResult build(final Specification specification)
  {
    final long issued = System.currentTimeMillis();

    final JwtBuilder jwtBuilder =
        Jwts.builder()
            .setAudience(specification.targetApplicationName)
            .setSubject(specification.tenant)
            .claim(TokenConstants.JWT_VERSION_CLAIM, TokenConstants.VERSION)
            .claim(TokenConstants.JWT_CONTENT_CLAIM, specification.role)
            .setIssuer(TokenType.SYSTEM.getIssuer())
            .setIssuedAt(new Date(issued))
            .signWith(SignatureAlgorithm.RS512, specification.privateKey);
    if (specification.secondsToLive <= 0) {
      throw new IllegalArgumentException("token secondsToLive must be positive.");
    }

    final Date expiration = new Date(issued + TimeUnit.SECONDS.toMillis(specification.secondsToLive));
    jwtBuilder.setExpiration(expiration);

    return new TokenSerializationResult(TokenConstants.PREFIX + jwtBuilder.compact(), expiration);
  }
}
