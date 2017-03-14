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
package io.mifos.anubis.security;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.FilterInvocation;

import java.util.Collection;

/**
 * @author Myrle Krantz
 */
public class UrlPermissionChecker implements AccessDecisionVoter<FilterInvocation> {
  @Override public boolean supports(final ConfigAttribute attribute) {
    return attribute.getAttribute().equals(ApplicationPermission.URL_AUTHORITY);
  }

  @Override public boolean supports(final Class<?> clazz) {
    return FilterInvocation.class.isAssignableFrom(clazz);
  }

  @Override public int vote(
      final Authentication unAuthentication,
      final FilterInvocation filterInvocation,
      final Collection<ConfigAttribute> attributes) {
    if (!AnubisAuthentication.class.isAssignableFrom(unAuthentication.getClass()))
      return ACCESS_ABSTAIN;

    if (filterInvocation == null)
      return ACCESS_ABSTAIN;

    final AnubisAuthentication authentication = (AnubisAuthentication) unAuthentication;

    final Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
    return authorities.stream()
        .map(x -> (ApplicationPermission)x)
        .filter(x -> x.matches(filterInvocation, authentication.getPrincipal()))
        .findAny()
        .map(x -> ACCESS_GRANTED).orElse(ACCESS_DENIED);
  }
}
