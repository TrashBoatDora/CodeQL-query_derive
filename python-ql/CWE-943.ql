//number of apis 76
import python
import semmle.python.ApiGraphs

predicate targetApi(API::Node api, string qn) {
  api = API::moduleImport("sqlite3").getMember("Cursor").getMember("execute") and qn = "sqlite3.Cursor.execute" or
  api = API::moduleImport("sqlite3").getMember("Cursor").getMember("executemany") and qn = "sqlite3.Cursor.executemany" or
  api = API::moduleImport("sqlite3").getMember("Connection").getMember("execute") and qn = "sqlite3.Connection.execute" or
  api = API::moduleImport("sqlite3").getMember("Connection").getMember("executemany") and qn = "sqlite3.Connection.executemany" or
  api = API::moduleImport("sqlite3").getMember("Connection").getMember("executescript") and qn = "sqlite3.Connection.executescript" or
  api = API::moduleImport("psycopg2").getMember("extensions").getMember("cursor").getMember("execute") and qn = "psycopg2.extensions.cursor.execute" or
  api = API::moduleImport("psycopg2").getMember("extensions").getMember("cursor").getMember("executemany") and qn = "psycopg2.extensions.cursor.executemany" or
  api = API::moduleImport("psycopg2").getMember("sql").getMember("SQL") and qn = "psycopg2.sql.SQL" or
  api = API::moduleImport("psycopg2").getMember("sql").getMember("Identifier") and qn = "psycopg2.sql.Identifier" or
  api = API::moduleImport("psycopg2").getMember("sql").getMember("Literal") and qn = "psycopg2.sql.Literal" or
  api = API::moduleImport("mysql").getMember("connector").getMember("cursor").getMember("MySQLCursor").getAnInstance().getMember("execute") and qn = "mysql.connector.cursor.MySQLCursor.execute" or
  api = API::moduleImport("mysql").getMember("connector").getMember("cursor").getMember("MySQLCursor").getAnInstance().getMember("executemany") and qn = "mysql.connector.cursor.MySQLCursor.executemany" or
  api = API::moduleImport("mariadb").getMember("Cursor").getAnInstance().getMember("execute") and qn = "mariadb.Cursor.execute" or
  api = API::moduleImport("mariadb").getMember("Cursor").getAnInstance().getMember("executemany") and qn = "mariadb.Cursor.executemany" or
  api = API::moduleImport("pymysql").getMember("cursors").getMember("Cursor").getAnInstance().getMember("execute") and qn = "pymysql.cursors.Cursor.execute" or
  api = API::moduleImport("pymysql").getMember("cursors").getMember("Cursor").getAnInstance().getMember("executemany") and qn = "pymysql.cursors.Cursor.executemany" or
  api = API::moduleImport("MySQLdb").getMember("cursors").getMember("Cursor").getAnInstance().getMember("execute") and qn = "MySQLdb.cursors.Cursor.execute" or
  api = API::moduleImport("MySQLdb").getMember("cursors").getMember("Cursor").getAnInstance().getMember("executemany") and qn = "MySQLdb.cursors.Cursor.executemany" or
  api = API::moduleImport("cx_Oracle").getMember("Cursor").getMember("execute") and qn = "cx_Oracle.Cursor.execute" or
  api = API::moduleImport("cx_Oracle").getMember("Cursor").getMember("executemany") and qn = "cx_Oracle.Cursor.executemany" or
  api = API::moduleImport("oracledb").getMember("Cursor").getAnInstance().getMember("execute") and qn = "oracledb.Cursor.execute" or
  api = API::moduleImport("oracledb").getMember("Cursor").getAnInstance().getMember("executemany") and qn = "oracledb.Cursor.executemany" or
  api = API::moduleImport("asyncpg").getMember("Connection").getAnInstance().getMember("execute") and qn = "asyncpg.Connection.execute" or
  api = API::moduleImport("asyncpg").getMember("Connection").getAnInstance().getMember("executemany") and qn = "asyncpg.Connection.executemany" or
  api = API::moduleImport("asyncpg").getMember("Connection").getAnInstance().getMember("fetch") and qn = "asyncpg.Connection.fetch" or
  api = API::moduleImport("asyncpg").getMember("Connection").getAnInstance().getMember("fetchrow") and qn = "asyncpg.Connection.fetchrow" or
  api = API::moduleImport("asyncpg").getMember("Connection").getAnInstance().getMember("fetchval") and qn = "asyncpg.Connection.fetchval" or
  api = API::moduleImport("aiomysql").getMember("cursors").getMember("Cursor").getAnInstance().getMember("execute") and qn = "aiomysql.cursors.Cursor.execute" or
  api = API::moduleImport("aiomysql").getMember("cursors").getMember("Cursor").getAnInstance().getMember("executemany") and qn = "aiomysql.cursors.Cursor.executemany" or
  api = API::moduleImport("aiosqlite").getMember("Connection").getAnInstance().getMember("execute") and qn = "aiosqlite.Connection.execute" or
  api = API::moduleImport("sqlalchemy").getMember("engine").getMember("Connection").getAnInstance().getMember("execute") and qn = "sqlalchemy.engine.Connection.execute" or
  api = API::moduleImport("sqlalchemy").getMember("engine").getMember("Engine").getAnInstance().getMember("execute") and qn = "sqlalchemy.engine.Engine.execute" or
  api = API::moduleImport("sqlalchemy").getMember("orm").getMember("Session").getAnInstance().getMember("execute") and qn = "sqlalchemy.orm.Session.execute" or
  api = API::moduleImport("sqlalchemy").getMember("orm").getMember("Session").getAnInstance().getMember("query") and qn = "sqlalchemy.orm.Session.query" or
  api = API::moduleImport("sqlalchemy").getMember("orm").getMember("Query").getAnInstance().getMember("filter") and qn = "sqlalchemy.orm.Query.filter" or
  api = API::moduleImport("sqlalchemy").getMember("orm").getMember("Query").getAnInstance().getMember("filter_by") and qn = "sqlalchemy.orm.Query.filter_by" or
  api = API::moduleImport("sqlalchemy").getMember("orm").getMember("Query").getAnInstance().getMember("from_statement") and qn = "sqlalchemy.orm.Query.from_statement" or
  api = API::moduleImport("sqlalchemy").getMember("sql").getMember("expression").getMember("text") and qn = "sqlalchemy.sql.expression.text" or
  api = API::moduleImport("sqlalchemy").getMember("text") and qn = "sqlalchemy.text" or
  api = API::moduleImport("sqlalchemy").getMember("sql").getMember("select") and qn = "sqlalchemy.sql.select" or
  api = API::moduleImport("sqlalchemy").getMember("sql").getMember("insert") and qn = "sqlalchemy.sql.insert" or
  api = API::moduleImport("sqlalchemy").getMember("sql").getMember("update") and qn = "sqlalchemy.sql.update" or
  api = API::moduleImport("sqlalchemy").getMember("sql").getMember("delete") and qn = "sqlalchemy.sql.delete" or
  api = API::moduleImport("sqlalchemy").getMember("sql").getMember("expression").getMember("bindparam") and qn = "sqlalchemy.sql.expression.bindparam" or
  api = API::moduleImport("sqlalchemy").getMember("sql").getMember("elements").getMember("literal_column") and qn = "sqlalchemy.sql.elements.literal_column" or
  api = API::moduleImport("django").getMember("db").getMember("models").getMember("Manager").getAnInstance().getMember("raw") and qn = "django.db.models.Manager.raw" or
  api = API::moduleImport("django").getMember("db").getMember("models").getMember("query").getMember("RawQuerySet") and qn = "django.db.models.query.RawQuerySet" or
  api = API::moduleImport("django").getMember("db").getMember("models").getMember("expressions").getMember("RawSQL") and qn = "django.db.models.expressions.RawSQL" or
  api = API::moduleImport("django").getMember("db").getMember("models").getMember("query").getMember("QuerySet").getAnInstance().getMember("extra") and qn = "django.db.models.query.QuerySet.extra" or
  api = API::moduleImport("django").getMember("db").getMember("models").getMember("query").getMember("QuerySet").getAnInstance().getMember("filter") and qn = "django.db.models.query.QuerySet.filter" or
  api = API::moduleImport("django").getMember("db").getMember("models").getMember("query").getMember("QuerySet").getAnInstance().getMember("exclude") and qn = "django.db.models.query.QuerySet.exclude" or
  api = API::moduleImport("django").getMember("db").getMember("models").getMember("query").getMember("QuerySet").getAnInstance().getMember("get") and qn = "django.db.models.query.QuerySet.get" or
  api = API::moduleImport("pymongo").getMember("collection").getMember("Collection").getAnInstance().getMember("find") and qn = "pymongo.collection.Collection.find" or
  api = API::moduleImport("pymongo").getMember("collection").getMember("Collection").getAnInstance().getMember("find_one") and qn = "pymongo.collection.Collection.find_one" or
  api = API::moduleImport("pymongo").getMember("collection").getMember("Collection").getAnInstance().getMember("aggregate") and qn = "pymongo.collection.Collection.aggregate" or
  api = API::moduleImport("pymongo").getMember("collection").getMember("Collection").getAnInstance().getMember("update_one") and qn = "pymongo.collection.Collection.update_one" or
  api = API::moduleImport("pymongo").getMember("collection").getMember("Collection").getAnInstance().getMember("update_many") and qn = "pymongo.collection.Collection.update_many" or
  api = API::moduleImport("pymongo").getMember("collection").getMember("Collection").getAnInstance().getMember("delete_one") and qn = "pymongo.collection.Collection.delete_one" or
  api = API::moduleImport("pymongo").getMember("collection").getMember("Collection").getAnInstance().getMember("delete_many") and qn = "pymongo.collection.Collection.delete_many" or
  api = API::moduleImport("pymongo").getMember("database").getMember("Database").getAnInstance().getMember("command") and qn = "pymongo.database.Database.command" or
  api = API::moduleImport("motor").getMember("motor_asyncio").getMember("AsyncIOMotorCollection").getAnInstance().getMember("find") and qn = "motor.motor_asyncio.AsyncIOMotorCollection.find" or
  api = API::moduleImport("motor").getMember("motor_asyncio").getMember("AsyncIOMotorCollection").getAnInstance().getMember("aggregate") and qn = "motor.motor_asyncio.AsyncIOMotorCollection.aggregate" or
  api = API::moduleImport("whoosh").getMember("qparser").getMember("QueryParser").getAnInstance().getMember("parse") and qn = "whoosh.qparser.QueryParser.parse" or
  api = API::moduleImport("pysolr").getMember("Solr").getAnInstance().getMember("search") and qn = "pysolr.Solr.search" or
  api = API::moduleImport("neo4j").getMember("Session").getAnInstance().getMember("run") and qn = "neo4j.Session.run" or
  api = API::moduleImport("neo4j").getMember("AsyncSession").getAnInstance().getMember("run") and qn = "neo4j.AsyncSession.run" or
  api = API::moduleImport("cassandra").getMember("cluster").getMember("Session").getMember("execute") and qn = "cassandra.cluster.Session.execute" or
  api = API::moduleImport("influxdb").getMember("InfluxDBClient").getAnInstance().getMember("query") and qn = "influxdb.InfluxDBClient.query" or
  api = API::moduleImport("ldap3").getMember("Connection").getAnInstance().getMember("search") and qn = "ldap3.Connection.search" or
  api = API::moduleImport("pymssql").getMember("Cursor").getMember("execute") and qn = "pymssql.Cursor.execute" or
  api = API::moduleImport("peewee").getMember("Database").getAnInstance().getMember("execute_sql") and qn = "peewee.Database.execute_sql" or
  api = API::moduleImport("peewee").getMember("Model").getMember("raw") and qn = "peewee.Model.raw" or
  api = API::moduleImport("pony").getMember("orm").getMember("select") and qn = "pony.orm.select" or
  api = API::moduleImport("pandas").getMember("read_sql") and qn = "pandas.read_sql" or
  api = API::moduleImport("pandas").getMember("read_sql_query") and qn = "pandas.read_sql_query" or
  api = API::moduleImport("pandas").getMember("read_sql_table") and qn = "pandas.read_sql_table" or
  api = API::moduleImport("psycopg").getMember("Connection").getAnInstance().getMember("execute") and qn = "psycopg.Connection.execute" or
  api = API::moduleImport("psycopg").getMember("Cursor").getAnInstance().getMember("execute") and qn = "psycopg.Cursor.execute" or
  api = API::moduleImport("psycopg").getMember("AsyncConnection").getAnInstance().getMember("execute") and qn = "psycopg.AsyncConnection.execute" or
  api = API::moduleImport("psycopg").getMember("AsyncCursor").getAnInstance().getMember("execute") and qn = "psycopg.AsyncCursor.execute" or
  api = API::moduleImport("pyodbc").getMember("Cursor").getAnInstance().getMember("execute") and qn = "pyodbc.Cursor.execute" or
  api = API::moduleImport("pyodbc").getMember("Cursor").getAnInstance().getMember("executemany") and qn = "pyodbc.Cursor.executemany" or
  api = API::moduleImport("dataset").getMember("Database").getAnInstance().getMember("query") and qn = "dataset.Database.query" or
  api = API::moduleImport("records").getMember("Database").getAnInstance().getMember("query") and qn = "records.Database.query" or
  api = API::moduleImport("django").getMember("db").getMember("backends").getMember("utils").getMember("CursorWrapper").getAnInstance().getMember("execute") and qn = "django.db.backends.utils.CursorWrapper.execute" or
  api = API::moduleImport("django").getMember("db").getMember("backends").getMember("utils").getMember("CursorWrapper").getAnInstance().getMember("executemany") and qn = "django.db.backends.utils.CursorWrapper.executemany" or
  api = API::moduleImport("django").getMember("db").getMember("connection").getMember("cursor") and qn = "django.db.connection.cursor" or
  api = API::moduleImport("elasticsearch").getMember("Elasticsearch").getAnInstance().getMember("search") and qn = "elasticsearch.Elasticsearch.search" or
  api = API::moduleImport("elasticsearch").getMember("Elasticsearch").getAnInstance().getMember("msearch") and qn = "elasticsearch.Elasticsearch.msearch" or
  api = API::moduleImport("elasticsearch").getMember("Elasticsearch").getAnInstance().getMember("count") and qn = "elasticsearch.Elasticsearch.count" or
  api = API::moduleImport("elasticsearch").getMember("Elasticsearch").getAnInstance().getMember("search_template") and qn = "elasticsearch.Elasticsearch.search_template" or
  api = API::moduleImport("elasticsearch").getMember("Elasticsearch").getAnInstance().getMember("msearch_template") and qn = "elasticsearch.Elasticsearch.msearch_template" or
  api = API::moduleImport("elasticsearch").getMember("Elasticsearch").getAnInstance().getMember("sql").getAnInstance().getMember("query") and qn = "elasticsearch.Elasticsearch.sql.query" or
  api = API::moduleImport("elasticsearch_dsl").getMember("Search").getAnInstance().getMember("execute") and qn = "elasticsearch_dsl.Search.execute" or
  api = API::moduleImport("py2neo").getMember("Graph").getAnInstance().getMember("run") and qn = "py2neo.Graph.run" or
  api = API::moduleImport("gremlin_python").getMember("driver").getMember("client").getMember("Client").getAnInstance().getMember("submit") and qn = "gremlin_python.driver.client.Client.submit" or
  api = API::moduleImport("influxdb_client").getMember("client").getMember("query").getMember("QueryApi").getAnInstance().getMember("query") and qn = "influxdb_client.client.query.QueryApi.query" or
  api = API::moduleImport("ldap").getMember("LDAPObject").getAnInstance().getMember("search_ext_s") and qn = "ldap.LDAPObject.search_ext_s" or
  api = API::moduleImport("tortoise").getMember("contrib").getMember("pylint").getMember("Model").getAnInstance().getMember("raw") and qn = "tortoise.contrib.pylint.Model.raw" or
  api = API::moduleImport("tortoise").getMember("backends").getMember("base").getMember("client").getMember("BaseDBAsyncClient").getAnInstance().getMember("execute_query") and qn = "tortoise.backends.base.client.BaseDBAsyncClient.execute_query" or
  api = API::moduleImport("pony").getMember("orm").getMember("db").getAnInstance().getMember("execute") and qn = "pony.orm.db.execute" or
  api = API::moduleImport("orator").getMember("DatabaseManager").getAnInstance().getMember("select") and qn = "orator.DatabaseManager.select" or
  api = API::moduleImport("orator").getMember("DatabaseManager").getAnInstance().getMember("statement") and qn = "orator.DatabaseManager.statement" or
  api = API::moduleImport("google").getMember("cloud").getMember("bigquery").getMember("Client").getAnInstance().getMember("query") and qn = "google.cloud.bigquery.Client.query" or
  api = API::moduleImport("graphql").getMember("Client").getAnInstance().getMember("execute") and qn = "graphql.Client.execute" or
  api = API::moduleImport("gql").getMember("Client").getAnInstance().getMember("execute") and qn = "gql.Client.execute" or
  api = API::moduleImport("sqlmodel").getMember("Session").getAnInstance().getMember("exec") and qn = "sqlmodel.Session.exec"

}
from API::Node api, DataFlow::CallCfgNode n, Call c, Function f,
    BasicBlock bb, string qn, string path, int sl, int sc, int el, int ec
where
  targetApi(api, qn) and
  n = api.getACall() and
  c = n.asExpr() and
  bb = n.asCfgNode().getBasicBlock() and
  bb.hasLocationInfo(path, sl, sc, el, ec) and
  f.getBody().contains(c)
select "path: "+ path,"call function: " + c.getLocation().getStartLine()+":"+c.getLocation().getStartColumn()+
"-"+c.getLocation().getEndLine()+":"+c.getLocation().getEndColumn()
,"call in function: " + f.getName()+"@" +f.getLocation().getStartLine()+"-"+f.getLastStatement().getLocation().getEndLine()
, "callee=" + qn, "basic block: "+sl+":"+sc+"-"+el+":"+ec
        