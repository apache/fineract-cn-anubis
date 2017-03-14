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
package io.mifos.anubis.repository;

import com.datastax.driver.core.*;
import com.datastax.driver.core.querybuilder.QueryBuilder;
import com.datastax.driver.core.querybuilder.Select;
import com.datastax.driver.core.schemabuilder.SchemaBuilder;
import io.mifos.anubis.api.v1.TokenConstants;
import io.mifos.anubis.api.v1.domain.Signature;
import io.mifos.anubis.config.TenantSignatureProvider;
import io.mifos.core.cassandra.core.CassandraSessionProvider;
import io.mifos.core.lang.ApplicationName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.math.BigInteger;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * @author Myrle Krantz
 */
@Component
public class TenantAuthorizationDataRepository implements TenantSignatureProvider {
  private final String tableName;
  private final CassandraSessionProvider cassandraSessionProvider;

  //So that the query only has to be prepared once and the Cassandra driver stops writing warnings into my logfiles.
  private final Map<String, Select.Where> versionToSignatureQueryMap = new HashMap<>();

  @Autowired
  public TenantAuthorizationDataRepository(
      final ApplicationName applicationName,
      final CassandraSessionProvider cassandraSessionProvider)
  {
    tableName = applicationName.getServiceName() + "_authorization_v1_data";
    this.cassandraSessionProvider = cassandraSessionProvider;
  }

  public void provisionTenant(final BigInteger isisPublicKeyModulus, final BigInteger isisPublicKeyExponent) {
    final Session session = cassandraSessionProvider.getTenantSession();

    createTable(session);
    createEntry(session, isisPublicKeyModulus, isisPublicKeyExponent);
  }

  private void createTable(final Session tenantSession) {

    final String createTenantsTable = SchemaBuilder
        .createTable(tableName)
        .ifNotExists()
        .addPartitionKey("version", DataType.text())
        .addColumn("public_key_mod", DataType.varint())
        .addColumn("public_key_exp", DataType.varint())
        .buildInternal();

    tenantSession.execute(createTenantsTable);
  }

  private void createEntry(final Session tenantSession,
      final BigInteger publicKeyModulus,
      final BigInteger publicKeyExponent)
  {

    final ResultSet versionCount =
        tenantSession.execute("SELECT count(*) FROM " + this.tableName + " WHERE version = '" + TokenConstants.VERSION + "'");
    final Long value = versionCount.one().get(0, Long.class);
    if (value == 0L) {
      //There will only be one entry in this table per version.
      final BoundStatement tenantCreationStatement =
          tenantSession.prepare("INSERT INTO " + tableName + " ("
              + "version, "
              + "public_key_mod, "
              + "public_key_exp)"
              + "VALUES (?, ?, ?)").bind();
      completeBoundStatement(tenantCreationStatement, publicKeyModulus, publicKeyExponent);

      tenantSession.execute(tenantCreationStatement);
    } else {
      final BoundStatement tenantUpdateStatement =
          tenantSession.prepare("UPDATE " + tableName + " SET "
              + " public_key_mod = ?, "
              + " public_key_exp = ? "
              + " WHERE version = ?").bind();
      completeBoundStatement(tenantUpdateStatement, publicKeyModulus, publicKeyExponent);

      tenantSession.execute(tenantUpdateStatement);
    }
  }

  private void completeBoundStatement(
      final BoundStatement tenantCreationStatement,
      final BigInteger publicKeyModulus,
      final BigInteger publicKeyExponent) {
    tenantCreationStatement.setString("version", TokenConstants.VERSION);
    tenantCreationStatement.setVarint("public_key_mod", publicKeyModulus);
    tenantCreationStatement.setVarint("public_key_exp", publicKeyExponent);
  }

  @Override
  public Optional<Signature> getSignature(final String version)
  {
    final Session tenantSession = cassandraSessionProvider.getTenantSession();
    final Select.Where query = versionToSignatureQueryMap.computeIfAbsent(version, versionKey ->
        QueryBuilder.select().from(tableName).where(QueryBuilder.eq("version", versionKey)));
    final Row result = tenantSession.execute(query).one();
    if (result == null)
      return Optional.empty();

    final BigInteger publicKeyMod = result.get("public_key_mod", BigInteger.class);
    final BigInteger publicKeyExp = result.get("public_key_exp", BigInteger.class);

    Assert.notNull(publicKeyMod);
    Assert.notNull(publicKeyExp);

    return Optional.of(new Signature(publicKeyMod, publicKeyExp));
  }
}
