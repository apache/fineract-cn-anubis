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
import io.mifos.core.lang.ServiceException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.annotation.Nullable;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.math.BigInteger;
import java.util.Optional;

import static io.mifos.anubis.api.v1.client.Anubis.TENANT_PUBLIC_KEY_EXPONENT_HEADER;
import static io.mifos.anubis.api.v1.client.Anubis.TENANT_PUBLIC_KEY_MODULUS_HEADER;


/**
 * @author Myrle Krantz
 */
@Component
public class InitializationFilter extends OncePerRequestFilter {

  final private TenantAuthorizationDataRepository tenantAuthorizationDataRepository;

  @Autowired
  public InitializationFilter(
      final TenantAuthorizationDataRepository tenantAuthorizationDataRepository) {
    super();
    this.tenantAuthorizationDataRepository = tenantAuthorizationDataRepository;
  }

  @Override
  protected void doFilterInternal(final HttpServletRequest request,
      final HttpServletResponse response,
      final FilterChain filterChain) throws ServletException,
      IOException {
    final String method = request.getMethod();

    if (method.equals("POST")) {
      final Optional<BigInteger> tenantPublicKeyExponent =
          toBigInteger(request.getHeader(TENANT_PUBLIC_KEY_EXPONENT_HEADER));
      final Optional<BigInteger> tenantPublicKeyModulus =
          toBigInteger(request.getHeader(TENANT_PUBLIC_KEY_MODULUS_HEADER));

      if (!tenantPublicKeyExponent.isPresent()) {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST,
            "Header [" + TENANT_PUBLIC_KEY_EXPONENT_HEADER + "] must be a valid big integer.");
      } else if (!tenantPublicKeyModulus.isPresent()) {
        response.sendError(HttpServletResponse.SC_BAD_REQUEST,
            "Header [" + TENANT_PUBLIC_KEY_MODULUS_HEADER + "] must be a valid big integer.");
      } else {
          //NOTE: we are provisioning, whether the tenant is already provisioned or not. This is
          // for the case that tenant public key has for some reason changed, and need to be
          // re-broadcast.
        try {
          tenantAuthorizationDataRepository
                  .provisionTenant(tenantPublicKeyModulus.get(),
                          tenantPublicKeyExponent.get());
        }
        catch (final ServiceException e)
        {
          response.sendError(e.serviceError().getCode(), e.serviceError().getMessage());
        }
        filterChain.doFilter(request, response);
      }
    }
    else
    {
      filterChain.doFilter(request, response);
    }
  }

  private Optional<BigInteger> toBigInteger(@Nullable final String value) {
    if (value == null)
      return Optional.empty();
    else
    {
      try {
        return Optional.of(new BigInteger(value));
      }
      catch (final NumberFormatException e)
      {
        return Optional.empty();
      }
    }
  }
}
