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

import com.google.gson.Gson;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.mifos.anubis.api.v1.TokenConstants;
import io.mifos.anubis.api.v1.domain.TokenContent;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.stereotype.Component;

import java.security.PrivateKey;
import java.util.Date;
import java.util.concurrent.TimeUnit;

/**
 * @author Myrle Krantz
 */
@SuppressWarnings({"WeakerAccess", "unused"})
@Component
public class TenantAccessTokenSerializer {

  final private Gson gson;

  @Autowired
  public TenantAccessTokenSerializer(final @Qualifier("anubisGson") Gson gson) {
    this.gson = gson;
  }


  public static class Specification {
    private PrivateKey privateKey;
    private String user;
    private TokenContent tokenContent;
    private long secondsToLive;

    public Specification setPrivateKey(final PrivateKey privateKey) {
      this.privateKey = privateKey;
      return this;
    }

    public Specification setUser(final String user) {
      this.user = user;
      return this;
    }

    public Specification setTokenContent(final TokenContent tokenContent) {
      this.tokenContent = tokenContent;
      return this;
    }

    public Specification setSecondsToLive(final long secondsToLive) {
      this.secondsToLive = secondsToLive;
      return this;
    }
  }

  public TokenSerializationResult build(final Specification specification)
  {
    final long issued = System.currentTimeMillis();

    final String serializedTokenContent = gson.toJson(specification.tokenContent);

    final JwtBuilder jwtBuilder =
        Jwts.builder()
            .setSubject(specification.user)
            .claim(TokenConstants.JWT_VERSION_CLAIM, TokenConstants.VERSION)
            .claim(TokenConstants.JWT_CONTENT_CLAIM, serializedTokenContent)
            .setIssuer(TokenType.TENANT.getIssuer())
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
