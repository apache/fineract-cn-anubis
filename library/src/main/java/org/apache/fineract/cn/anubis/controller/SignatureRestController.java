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
package org.apache.fineract.cn.anubis.controller;

import org.apache.fineract.cn.anubis.annotation.AcceptedTokenType;
import org.apache.fineract.cn.anubis.annotation.Permittable;
import org.apache.fineract.cn.anubis.api.v1.domain.ApplicationSignatureSet;
import org.apache.fineract.cn.anubis.api.v1.domain.Signature;
import org.apache.fineract.cn.anubis.config.TenantSignatureRepository;
import org.apache.fineract.cn.lang.ServiceException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * @author Myrle Krantz
 */
@RestController
@RequestMapping()
public class SignatureRestController {
  final private TenantSignatureRepository tenantSignatureRepository;

  @Autowired
  public SignatureRestController(final TenantSignatureRepository tenantSignatureRepository) {
    this.tenantSignatureRepository = tenantSignatureRepository;
  }

  @Permittable(AcceptedTokenType.SYSTEM)
  @RequestMapping(
          value = "/signatures",
          method = RequestMethod.GET,
          consumes = {MediaType.ALL_VALUE},
          produces = {MediaType.APPLICATION_JSON_VALUE})
  public
  @ResponseBody ResponseEntity<List<String>> getAllSignatureSets() {
    return ResponseEntity.ok(tenantSignatureRepository.getAllSignatureSetKeyTimestamps());
  }

  @Permittable(AcceptedTokenType.SYSTEM)
  @RequestMapping(value = "/signatures/{timestamp}", method = RequestMethod.GET,
          consumes = {MediaType.ALL_VALUE},
          produces = {MediaType.APPLICATION_JSON_VALUE})
  public
  @ResponseBody ResponseEntity<ApplicationSignatureSet> getSignatureSet(@PathVariable("timestamp") final String timestamp)
  {
    return tenantSignatureRepository.getSignatureSet(timestamp)
            .map(ResponseEntity::ok)
            .orElseThrow(() -> ServiceException.notFound("Signature for timestamp '" + timestamp + "' not found."));
  }

  @Permittable(AcceptedTokenType.SYSTEM)
  @RequestMapping(value = "/signatures/_latest", method = RequestMethod.GET,
          consumes = {MediaType.ALL_VALUE},
          produces = {MediaType.APPLICATION_JSON_VALUE})
  public
  @ResponseBody ResponseEntity<ApplicationSignatureSet> getLatestSignatureSet()
  {
    return tenantSignatureRepository.getLatestSignatureSet()
            .map(ResponseEntity::ok)
            .orElseThrow(() -> ServiceException.notFound("No valid signature found."));
  }

  @Permittable(AcceptedTokenType.SYSTEM)
  @RequestMapping(value = "/signatures/{timestamp}", method = RequestMethod.DELETE,
          consumes = {MediaType.ALL_VALUE},
          produces = {MediaType.APPLICATION_JSON_VALUE})
  public
  @ResponseBody ResponseEntity<Void> deleteSignatureSet(@PathVariable("timestamp") final String timestamp)
  {
    tenantSignatureRepository.deleteSignatureSet(timestamp);
    return ResponseEntity.accepted().build();
  }

  @Permittable(AcceptedTokenType.SYSTEM)
  @RequestMapping(value = "/signatures/{timestamp}/application", method = RequestMethod.GET,
          consumes = {MediaType.ALL_VALUE},
          produces = {MediaType.APPLICATION_JSON_VALUE})
  public
  @ResponseBody ResponseEntity<Signature> getApplicationSignature(@PathVariable("timestamp") final String timestamp)
  {
    return tenantSignatureRepository.getApplicationSignature(timestamp)
            .map(ResponseEntity::ok)
            .orElseThrow(() -> ServiceException.notFound("Signature for timestamp '" + timestamp + "' not found."));
  }

  @Permittable(AcceptedTokenType.SYSTEM)
  @RequestMapping(value = "/signatures/_latest/application", method = RequestMethod.GET,
          consumes = {MediaType.ALL_VALUE},
          produces = {MediaType.APPLICATION_JSON_VALUE})
  public
  @ResponseBody ResponseEntity<Signature> getLatestApplicationSignature()
  {
    return tenantSignatureRepository.getLatestApplicationSignature()
            .map(ResponseEntity::ok)
            .orElseThrow(() -> ServiceException.notFound("No valid signature found."));
  }
}