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
package io.mifos.anubis.api.v1.client;

import io.mifos.anubis.api.v1.domain.PermittableEndpoint;
import io.mifos.core.api.util.InvalidTokenException;
import org.springframework.cloud.netflix.feign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import java.math.BigInteger;
import java.util.List;

@SuppressWarnings("WeakerAccess")
@FeignClient
public interface Anubis {
  String ISIS_PUBLIC_KEY_MODULUS_HEADER = "X-Isis-Public-Key-Modulus";
  String ISIS_PUBLIC_KEY_EXPONENT_HEADER = "X-Isis-Public-Key-Exponent";

  @RequestMapping(
      value = "/permittables",
      method = RequestMethod.GET,
      consumes = MediaType.APPLICATION_JSON_VALUE,
      produces = MediaType.ALL_VALUE
  )
  List<PermittableEndpoint> getPermittableEndpoints();

  @RequestMapping(value = "/initialize", method = RequestMethod.POST,
      consumes = {MediaType.APPLICATION_JSON_VALUE},
      produces = {MediaType.ALL_VALUE})
  void initialize(
      @RequestHeader(ISIS_PUBLIC_KEY_MODULUS_HEADER) BigInteger isisKeyMod,
      @RequestHeader(ISIS_PUBLIC_KEY_EXPONENT_HEADER) BigInteger isisKeyExp)
      throws InvalidTokenException, TenantNotFoundException;
}
