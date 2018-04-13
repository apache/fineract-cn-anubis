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
package org.apache.fineract.cn.anubis;

import org.apache.fineract.cn.anubis.api.v1.client.Anubis;
import org.apache.fineract.cn.anubis.api.v1.client.AnubisApiFactory;
import org.apache.fineract.cn.anubis.api.v1.domain.PermittableEndpoint;
import org.junit.Assert;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

/**
 * @author Myrle Krantz
 */
public class TestPermittableEndpoints extends AbstractNoInitializeTest {
  @Test
  public void shouldFindPermittableEndpoints() throws Exception {
    final Anubis anubis = AnubisApiFactory.create(TestPermittableEndpoints.testEnvironment.serverURI(), logger);
    final List<PermittableEndpoint> permittableEndpoints = anubis.getPermittableEndpoints();
    Assert.assertNotNull(permittableEndpoints);
    Assert.assertEquals(6, permittableEndpoints.size());
    Assert.assertTrue(permittableEndpoints.containsAll(Arrays.asList(
        new PermittableEndpoint("anubis-v1/dummy", "GET"),
        new PermittableEndpoint("anubis-v1/dummy", "DELETE"),
        new PermittableEndpoint("anubis-v1/dummy", "POST"),
        new PermittableEndpoint("anubis-v1/parameterized/*/with/*/parameters", "GET", "endpointGroup"),
        new PermittableEndpoint("anubis-v1/parameterized/{useridentifier}/with/*/parameters", "GET", "endpointGroupWithParameters"))));
    Assert.assertFalse(permittableEndpoints.contains(new PermittableEndpoint("anubis-v1/systemendpoint", "POST")));
  }
}
