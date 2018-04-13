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
package org.apache.fineract.cn.anubis.api.v1.validation;


import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.time.DateTimeException;
import org.apache.fineract.cn.lang.DateConverter;

/**
 * @author Myrle Krantz
 */
@SuppressWarnings("WeakerAccess")
public class CheckKeyTimestamp implements ConstraintValidator<ValidKeyTimestamp, String> {
  @Override
  public void initialize(ValidKeyTimestamp constraintAnnotation) { }

  @Override
  public boolean isValid(final String value, final ConstraintValidatorContext context) {
    if (value == null)
      return false;
    try {
      final String timeString = value.replace('_', ':');
      DateConverter.fromIsoString(timeString);
      return true;
    }
    catch (final DateTimeException ignored) {
      return false;
    }
  }
}
