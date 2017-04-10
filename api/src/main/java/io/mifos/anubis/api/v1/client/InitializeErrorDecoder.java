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

import feign.Feign;
import feign.FeignException;
import feign.Response;
import feign.codec.ErrorDecoder;
import io.mifos.anubis.api.v1.domain.Signature;
import io.mifos.core.api.util.InvalidTokenException;
import org.apache.http.HttpStatus;

import java.lang.reflect.Method;

/**
 * @author Myrle Krantz
 */
class InitializeErrorDecoder implements ErrorDecoder {
  @Override public Exception decode(final String methodKey, final Response response) {
    try {
      final Method createSignatureSetMethod = Anubis.class.getDeclaredMethod("createSignatureSet", String.class, Signature.class);
      final String createSignatureSetMethodKey =  Feign.configKey(Anubis.class, createSignatureSetMethod);
      final Method initializeResourcesMethod = Anubis.class.getDeclaredMethod("initializeResources");
      final String initializeResourcesMethodKey =  Feign.configKey(Anubis.class, initializeResourcesMethod);
      if (createSignatureSetMethodKey.equals(methodKey) || initializeResourcesMethodKey.equals(methodKey))
      {
        if (response.status() == HttpStatus.SC_BAD_REQUEST)
          return new IllegalArgumentException();
        else if (response.status() == HttpStatus.SC_NOT_FOUND)
          return new TenantNotFoundException();
        else if (response.status() == HttpStatus.SC_FORBIDDEN)
          return new InvalidTokenException(response.reason());
      }

      return FeignException.errorStatus(methodKey, response);
    }
    catch (final NoSuchMethodException e) {
      throw new IllegalStateException("Could not find createSignatureSet method."); //TODO:
    }
  }
}
