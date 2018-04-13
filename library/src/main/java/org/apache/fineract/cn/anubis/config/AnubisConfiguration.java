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
package org.apache.fineract.cn.anubis.config;

import static org.apache.fineract.cn.anubis.config.AnubisConstants.LOGGER_NAME;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import org.apache.fineract.cn.cassandra.config.EnableCassandra;
import org.apache.fineract.cn.lang.config.EnableApplicationName;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author Myrle Krantz
 */
@Configuration
@EnableApplicationName
@EnableCassandra
@EnableConfigurationProperties(AnubisProperties.class)
public class AnubisConfiguration {

  @Bean(name = LOGGER_NAME)
  public Logger logger() {
    return LoggerFactory.getLogger(LOGGER_NAME);
  }

  @Bean()
  public Gson anubisGson()
  {
    return new GsonBuilder().create();
  }
}
