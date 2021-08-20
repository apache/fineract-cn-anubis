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

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import java.util.Collection;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * @author manoj
 */
@Service
public class AccountLevelAccessVerifierCustom {
    private final static String OWNER = "OWNER";

    @Value("${conf.enableAccountLevelAccessVerification}")
    private String isAccountLevelAccessVerificationEnabled;

    public void validate(String accountNo, String operation){
        if(!"true".equals(isAccountLevelAccessVerificationEnabled)) return;
        AnubisAuthentication authentication = (AnubisAuthentication)SecurityContextHolder.getContext().getAuthentication();
        String acctPermission = "ACCT_ACCESS_" + accountNo;
        final Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        final Set<String> accountOperation = authorities.stream()
                .map(x -> (ApplicationPermission) x)
                .filter(x -> x.matches(acctPermission, "get", authentication.getPrincipal().getForApplicationName(), authentication.getPrincipal()))
                .map(ApplicationPermission::getAccountOperation)
                .collect(Collectors.toSet());

        if(accountOperation.size() == 0  || !(accountOperation.contains(OWNER) || accountOperation.contains(operation))) {
            throw AccountLevelAccessDeniedException.internalError("Access Denied, " + operation + " on " + accountNo);
        }
    }
}
