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
package org.apache.fineract.cn.anubis.api.v1.domain;

import java.util.Set;

/**
 * @author manoj
 */
public class AccountAccess {
    private String number;
    private Set<String> access;

    public AccountAccess() {
    }

    public AccountAccess(String number, Set<String> access) {
        this.number = number;
        this.access = access;
    }

    public String getNumber() {
        return number;
    }

    public void setNumber(String number) {
        this.number = number;
    }

    public Set<String> getAccess() {
        return access;
    }

    public void setAccess(Set<String> access) {
        this.access = access;
    }
}
