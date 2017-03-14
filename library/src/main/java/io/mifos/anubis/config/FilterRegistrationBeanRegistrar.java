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
package io.mifos.anubis.config;

import io.mifos.anubis.filter.InitializationFilter;
import org.springframework.beans.factory.support.AbstractBeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ImportBeanDefinitionRegistrar;
import org.springframework.core.type.AnnotationMetadata;

import static org.springframework.beans.factory.config.BeanDefinition.SCOPE_SINGLETON;

/**
 * @author Myrle Krantz
 */
class FilterRegistrationBeanRegistrar implements ImportBeanDefinitionRegistrar {
  FilterRegistrationBeanRegistrar() { }

  @Override public void registerBeanDefinitions(final AnnotationMetadata importingClassMetadata,
      final BeanDefinitionRegistry registry) {

    final boolean includeInitializationFilter = (boolean)importingClassMetadata
        .getAnnotationAttributes(EnableAnubis.class.getTypeName())
        .get("storeTenantKeysAtInitialization");

    if (includeInitializationFilter) {
      final AbstractBeanDefinition beanDefinition = BeanDefinitionBuilder
          .rootBeanDefinition(this.getClass())
          .setFactoryMethod("initializationFilterRegistration")
          .addConstructorArgReference(InitializationFilter.class.getCanonicalName())
          .setScope(SCOPE_SINGLETON).getBeanDefinition();

      registry.registerBeanDefinition("initializationFilterRegistration", beanDefinition);
    }
  }

  @SuppressWarnings("SpringJavaAutowiringInspection")
  @Bean
  static FilterRegistrationBean initializationFilterRegistration(
      final InitializationFilter initializationFilter) {
    final FilterRegistrationBean registration = new FilterRegistrationBean();
    registration.setFilter(initializationFilter);
    registration.addUrlPatterns("/initialize");
    registration.setName("initializationFilter");
    registration.setOrder(Integer.MAX_VALUE); //After the tenant header filter and the security filter.
    return registration;
  }
}
