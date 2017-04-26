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

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Header;
import io.jsonwebtoken.Jwt;
import io.jsonwebtoken.Jwts;
import io.mifos.anubis.api.v1.TokenConstants;
import io.mifos.anubis.provider.InvalidKeyTimestampException;
import io.mifos.anubis.provider.TenantRsaKeyProvider;
import io.mifos.anubis.security.AmitAuthenticationException;
import io.mifos.anubis.token.TenantRefreshTokenSerializer.Specification;
import io.mifos.core.lang.security.RsaKeyPairFactory;
import io.mifos.core.test.domain.TimeStampChecker;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.Mockito;

import java.time.Duration;
import java.time.LocalDateTime;

/**
 * @author Myrle Krantz
 */
public class TenantRefreshTokenSerializerTest {

  private static final String APPLICATION_NAME = "mifosio-core";
  private static final int SECONDS_TO_LIVE = 15;
  private static final String USER = "who";
  private static RsaKeyPairFactory.KeyPairHolder keyPairHolder;

  @BeforeClass
  public static void initialize()
  {
    keyPairHolder = RsaKeyPairFactory.createKeyPair();
  }

  @Test
  public void shouldCreateValidRefreshToken() throws Exception {
    final Specification specification = getValidSpecification();
    final TenantRefreshTokenSerializer testSubject = getTestSubject();

    final TimeStampChecker timeStampChecker = TimeStampChecker.inTheFuture(Duration.ofSeconds(SECONDS_TO_LIVE));

    final TokenSerializationResult tokenSerializationResult = testSubject.build(specification);

    Assert.assertNotNull(tokenSerializationResult);

    final LocalDateTime expiration = tokenSerializationResult.getExpiration();
    timeStampChecker.assertCorrect(expiration);

    @SuppressWarnings("unchecked") final Jwt<Header, Claims> parsedToken = Jwts
            .parser()
            .setSigningKey(keyPairHolder.publicKey())
            .parse(tokenSerializationResult.getToken().substring("Bearer ".length()).trim());


    Assert.assertNotNull(parsedToken);
    Assert.assertEquals(APPLICATION_NAME, parsedToken.getBody().get("iss"));
    final Integer issued = (Integer) parsedToken.getBody().get("iat");
    Assert.assertNotNull(issued);
    final Integer expires = (Integer) parsedToken.getBody().get("exp");
    Assert.assertNotNull(expires);
    Assert.assertTrue(expires > issued);
    final String signatureTimestamp = parsedToken.getBody().get(TokenConstants.JWT_SIGNATURE_TIMESTAMP_CLAIM, String.class);
    Assert.assertEquals(keyPairHolder.getTimestamp(), signatureTimestamp);

    final TokenDeserializationResult tokenDeserializationResult = testSubject.deserialize(tokenSerializationResult.getToken());
    Assert.assertNotNull(tokenDeserializationResult);
    Assert.assertEquals(APPLICATION_NAME, tokenDeserializationResult.getSourceApplication());
    Assert.assertEquals(USER, tokenDeserializationResult.getUserIdentifier());
    Assert.assertEquals(tokenDeserializationResult.getExpiration(), tokenDeserializationResult.getExpiration());
  }

  @Test(expected = IllegalArgumentException.class)
  public void invalidSecondsToLiveCausesException() throws Exception {
    final Specification specification = getValidSpecification().setSecondsToLive(-1);
    final TenantRefreshTokenSerializer testSubject = getTestSubject();
    testSubject.build(specification);
  }

  @Test(expected = IllegalArgumentException.class)
  public void missingKeyTimestampCausesException() throws Exception {
    final Specification specification = getValidSpecification().setKeyTimestamp(null);
    final TenantRefreshTokenSerializer testSubject = getTestSubject();
    testSubject.build(specification);
  }

  @Test(expected = IllegalArgumentException.class)
  public void missingApplicationCausesException() throws Exception {
    final Specification specification = getValidSpecification().setSourceApplication(null);
    final TenantRefreshTokenSerializer testSubject = getTestSubject();
    testSubject.build(specification);
  }

  @Test(expected = IllegalArgumentException.class)
  public void missingPrivateKeyCausesException() throws Exception {
    final Specification specification = getValidSpecification().setPrivateKey(null);
    final TenantRefreshTokenSerializer testSubject = getTestSubject();
    testSubject.build(specification);
  }

  @Test(expected = AmitAuthenticationException.class)
  public void deserializeNullCausesAmitException() throws Exception {
    final TenantRefreshTokenSerializer testSubject = getTestSubject();
    testSubject.deserialize(null);
  }

  @Test(expected = AmitAuthenticationException.class)
  public void deserializeUnprefixedTokenCausesAmitException() throws Exception {
    final TenantRefreshTokenSerializer testSubject = getTestSubject();
    testSubject.deserialize("randostring");
  }

  @Test(expected = AmitAuthenticationException.class)
  public void tenantHasNotProvidedAPublicKeyDuringDeserializationCausesAmitException() throws Exception {
    final Specification specification = getValidSpecification();
    final TenantRsaKeyProvider tenantRsaKeyProvider = Mockito.mock(TenantRsaKeyProvider.class);
    Mockito.when(tenantRsaKeyProvider.getPublicKey(keyPairHolder.getTimestamp())).thenThrow(new IllegalArgumentException());

    final TenantRefreshTokenSerializer testSubject = new TenantRefreshTokenSerializer(tenantRsaKeyProvider);
    TokenSerializationResult tokenSerializationResult = testSubject.build(specification);
    testSubject.deserialize(tokenSerializationResult.getToken());
  }

  @Test(expected = AmitAuthenticationException.class)
  public void tenantHasNotProvidedAPublicKeyForKeyTimestampDuringDeserializationCausesAmitException() throws Exception {
    final Specification specification = getValidSpecification();
    final TenantRsaKeyProvider tenantRsaKeyProvider = Mockito.mock(TenantRsaKeyProvider.class);
    Mockito.when(tenantRsaKeyProvider.getPublicKey(keyPairHolder.getTimestamp())).thenThrow(new InvalidKeyTimestampException(""));

    final TenantRefreshTokenSerializer testSubject = new TenantRefreshTokenSerializer(tenantRsaKeyProvider);
    TokenSerializationResult tokenSerializationResult = testSubject.build(specification);
    testSubject.deserialize(tokenSerializationResult.getToken());
  }

  private Specification getValidSpecification() {
    return new Specification()
            .setUser(USER)
            .setKeyTimestamp(keyPairHolder.getTimestamp())
            .setSourceApplication(APPLICATION_NAME)
            .setPrivateKey(keyPairHolder.privateKey())
            .setSecondsToLive(SECONDS_TO_LIVE);
  }

  private TenantRefreshTokenSerializer getTestSubject() throws InvalidKeyTimestampException {
    final TenantRsaKeyProvider tenantRsaKeyProvider = Mockito.mock(TenantRsaKeyProvider.class);
    Mockito.when(tenantRsaKeyProvider.getPublicKey(keyPairHolder.getTimestamp())).thenReturn(keyPairHolder.publicKey());

    return new TenantRefreshTokenSerializer(tenantRsaKeyProvider);
  }
}
