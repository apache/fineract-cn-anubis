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
package io.mifos.anubis.filter;

import io.mifos.anubis.repository.TenantAuthorizationDataRepository;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.mockito.Mockito;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Collection;

import static io.mifos.anubis.api.v1.client.Anubis.ISIS_PUBLIC_KEY_EXPONENT_HEADER;
import static io.mifos.anubis.api.v1.client.Anubis.ISIS_PUBLIC_KEY_MODULUS_HEADER;
import static javax.servlet.http.HttpServletResponse.*;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.when;

/**
 * @author Myrle Krantz
 */
@RunWith(Parameterized.class)
public class InitializationFilterTest {

  private static class TestCase {
    BigInteger publicKeyMod = BigInteger.ONE;
    BigInteger publicKeyExp = BigInteger.TEN;
    int responseStatus = SC_OK;
    String method = "POST";

    TestCase publicKeyMod(final BigInteger newVal)
    {
      publicKeyMod = newVal;
      return this;
    }

    TestCase publicKeyExp(final BigInteger newVal)
    {
      publicKeyExp = newVal;
      return this;
    }

    TestCase responseStatus(final int newVal)
    {
      responseStatus = newVal;
      return this;
    }

    TestCase method(final String newVal)
    {
      method = newVal;
      return this;
    }
  }

  @Parameterized.Parameters
  public static Collection testCases() {
    final Collection<TestCase> ret = new ArrayList<>();

    ret.add(new TestCase());
    ret.add(new TestCase().method("GET"));
    ret.add(new TestCase().publicKeyExp(null).responseStatus(SC_BAD_REQUEST));
    ret.add(new TestCase().publicKeyMod(null).responseStatus(SC_BAD_REQUEST));


    return ret;
  }

  private final TestCase testCase;

  private TenantAuthorizationDataRepository tenantAuthorizationDataRepository;
  private HttpServletRequest request;
  private HttpServletResponse response;
  private FilterChain filterChain;

  public InitializationFilterTest(final TestCase testCase)
  {
    this.testCase = testCase;
  }

  @Before()
  public void setup()
  {
    tenantAuthorizationDataRepository = Mockito.mock(TenantAuthorizationDataRepository.class);

    request = Mockito.mock(HttpServletRequest.class);
    when(request.getMethod()).thenReturn(testCase.method);
    when(request.getHeader(ISIS_PUBLIC_KEY_EXPONENT_HEADER)).thenReturn(
        String.valueOf(testCase.publicKeyExp));
    when(request.getHeader(ISIS_PUBLIC_KEY_MODULUS_HEADER)).thenReturn(
        String.valueOf(testCase.publicKeyMod));

    response = Mockito.mock(HttpServletResponse.class);
    filterChain = Mockito.mock(FilterChain.class);
  }

  @Test()
  public void test() throws ServletException, IOException {

    final InitializationFilter testSubject = new InitializationFilter(tenantAuthorizationDataRepository);


    testSubject.doFilterInternal(request, response, filterChain);

    if (testCase.responseStatus == SC_OK  && testCase.method.equals("POST")) {
      Mockito.verify(tenantAuthorizationDataRepository)
          .provisionTenant(testCase.publicKeyMod, testCase.publicKeyExp);
      Mockito.verify(filterChain).doFilter(request, response);
    }
    else if (!testCase.method.equals("POST")) {
      Mockito.verify(filterChain).doFilter(request, response);
    }
    else
    {
      Mockito.verify(response).sendError(eq(testCase.responseStatus), any(String.class));
    }
  }
}
