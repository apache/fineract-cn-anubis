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
package org.apache.fineract.cn.anubis.api.v1;

/**
 * @author Myrle Krantz
 */
@SuppressWarnings("unused")
public interface TokenConstants {
  String NO_AUTHENTICATION = "N/A";
  String PREFIX = "Bearer ";

  String JWT_SIGNATURE_TIMESTAMP_CLAIM = "/fincn.apache.org/s";
  String JWT_ENDPOINT_SET_CLAIM = "/fincn.apache.org/e";
  String JWT_CONTENT_CLAIM = "/fincn.apache.org/c";
  String JWT_SOURCE_APPLICATION_CLAIM = "/fincn.apache.org/a";

  String REFRESH_TOKEN_COOKIE_NAME = "org.apache.fincn.refreshToken";
}
