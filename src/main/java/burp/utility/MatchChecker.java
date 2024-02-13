package burp.utility;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import burp.IExtensionHelpers;

public class MatchChecker {

    private Map<String, String[]> dbErrorPatterns;
    private Map<String, String[]> errorPatterns;
    private IExtensionHelpers helper;

    public MatchChecker(IExtensionHelpers helper) {
        this.helper = helper;
        this.dbErrorPatterns = new HashMap<>();
        this.errorPatterns = new HashMap<>();

        // Populate the map with combined error patterns
    // Populate the map with combined error patterns
dbErrorPatterns.put("all", new String[] {
    // Generic patterns
    "unclosed quotation mark",
    "unterminated string",
    "syntax error",
    "unexpected token",
    "column .+ not found",
    "table .+ not found",
    "invalid .+ data",
    "access denied",

    // Oracle patterns
    "ORA-00904",
    "ORA-01756",
    "ORA-00942",
    "ORA-00907",
    "ORA-01403",
    "ORA-01422",
    "ORA-00911",
    "ORA-06502",
    "ORA-(.*):",
    "invalid identifier",
    "PLS-00103: Encountered the symbol \"(.*)\" when expecting one of the following",
    "ORA-00904: invalid identifier: .*",
    "ORA-06502: PL/SQL: numeric or value error",

    // MySQL patterns
    "MySQL error",
    "Error Code: 1064",
    "Error Code: 1146",
    "Error Code: 1054",
    "Error Code: 1452",
    "Error Code: 1045",
    "Error Code: 1136",
    "MySQL syntax error",
    "Unknown column",
    "You have an error in your SQL syntax",
    "Table '(.*)' doesn't exist",
    "Unknown table '(.*)'",
    "Incorrect syntax near",
    "Access denied for user '(.*)'",
    "Unknown database '(.*)'",
    "Illegal mix of collations",
    "Can't find record",
    "Division by zero",

    // PostgreSQL patterns
    "SQLSTATE [22P01]",
    "PG::SyntaxError",
    "PG::UndefinedTable",
    "PG::UndefinedColumn",
    "PG::CardinalityViolation",
    "PG::InsufficientPrivilege",
    "PG::DatatypeMismatch",
    "syntax error at or near \"(.*)\"",
    "column \"(.*)\" does not exist",
    "unrecognized token: \"(.*)\"",
    "relation \"(.*)\" does not exist",
    "permission denied for relation \"(.*)\"",
    "invalid character in input string",

    // MSSQL patterns
    "Microsoft SQL Server Native Client 11.0",
    "Invalid column name",
    "Incorrect syntax near",
    "Table 'dbo.table_name' does not exist",
    "Cannot insert duplicate key row in object",
    "Violation of PRIMARY KEY constraint",
    "The INSERT statement conflicted with the FOREIGN KEY constraint",

    // Java
    "java\\.sql\\.SQLException",
    "org\\.springframework\\.jdbc\\.BadSqlGrammarException",
    "org\\.hibernate\\.exception\\.SQLGrammarException",
    "java.sql.SQLException: (.*)",
    "com.mysql.jdbc.exceptions.jdbc4.MySQLSyntaxErrorException: (.*)",
    "org.postgresql.util.PSQLException: (.*)",
    "com.microsoft.sqlserver.jdbc.SQLServerException: (.*)",
    "org.springframework.dao.DataAccessException: (.*)",
    "java.lang.IllegalStateException: PreparedStatement is closed",
    "com.google.inject.ProvisionException: Unable to provision, see the following errors",
    "java.lang.NullPointerException: null",
    "javax.persistence.PersistenceException: (.*)",

    // Python
    "psycopg2\\.ProgrammingError",
    "django\\.db\\.utils\\.IntegrityError",
    "sqlobject\\.SQLObjectIntegrityError",
    "sqlite3.OperationalError: (.*)",
    "psycopg2.errors.UndefinedTable: (.*)",
    "sqlalchemy.exc.ProgrammingError: (.*)",

    // PHP
    "MySQLi_Sql_Exception",
    "PDOException",
    "Doctrine\\\\DBAL\\\\Exception\\\\DriverException",
    "mysqli_real_query(): (.*) in",
    "SQL syntax error",

    "Undefined variable: (.*)",
    "A PHP Error was encountered",
    "Call to undefined function (.*)",
    "Warning: Cannot modify header information - headers already sent by (.*)",
    "Notice: Undefined index: (.*)",

    // Framework-specific
    "org\\.springframework\\.dao\\.DataIntegrityViolationException",
    "django\\.db\\.utils\\.OperationalError",
    "Illuminate\\\\Database\\\\QueryException",
    "SQLAlchemyError: (.*)",
    "OperationalError: (.*)",
    "ProgrammingError: (.*)",
    "IntegrityError: (.*)",
    "DataError: (.*)",
    "InvalidRequestError: (.*)",
    "MissingParameterError: (.*)",

    // Ruby
    "ActiveRecord::StatementInvalid: (.*)",
    "PG::ConnectionBad: (.*)",
    "Mysql2::Error: (.*)",

    // Node
    "SequelizeDatabaseError: (.*)",
    "pg-promise: error: (.*)",

    // General patterns
    "SQLSTATE \\[.*?\\]",
    "constraint violation",
    "duplicate key",
    "invalid query",
    "data truncated",
    "syntax error",

    //Spring:
    "org.springframework.jdbc.BadSqlGrammarException: (.*)",
    "org.springframework.dao.DataIntegrityViolationException: (.*)",
    "org.hibernate.exception.SQLGrammarException: (.*)",

    //Laravel:
    "Illuminate\\\\Database\\\\QueryException: \\\"(.*)\\\"",
    "PDOException: (.*)",
    "SQLSTATE[HY000]: General error: (.*)",

    //Express.js:
    "Error: ER_PARSE_ERROR: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version for the right syntax to use near '(.*)' at line (.*) (.*)",
    "Error: connect ECONNREFUSED (.*)",
    "Error: EACCES: permission denied, connect (.*)",

    //ASP.NET MVC:
    "System.Data.SqlClient.SqlException: (.*)",
    "System.Data.Entity.Core.EntityException: (.*)",
    "System.Data.Entity.Validation.DbEntityValidationException: (.*)",

    //Apache Tomcat:
    "java.sql.SQLException: Violation of primary key constraint '(.*)'",
    "java.lang.IllegalArgumentException: Invalid SQL statement (.*)",
    "javax.naming.NamingException: Cannot create connection to database server (.*)"

    });   

    errorPatterns.put("Common", new String[] {
        // ASP.NET verbose error patterns
        "Detailed Error Information",
        "Server Error in '/' Application",
        "Runtime Error",
        "Stack Trace",
        "Unhandled exception",
        "ASP.NET Version",
        "([A-Za-z]{1,32}\\.)+[A-Za-z]{0,32}\\(([A-Za-z0-9]+\\s+[A-Za-z0-9]+[,\\s]*)*\\)\\s+\\+{1}\\d+",
        "--- End of inner exception stack trace ---",
        // Java web application verbose error patterns
        "java.lang.Exception",
        "javax.servlet.ServletException",
        "Root Cause",
        "Stack Trace",
        "Unhandled exception",
        "Java Version",
        // Node.js verbose error patterns
        "Stack Trace",
        "Unhandled exception",
        "Node.js Version",
        // Tomcat verbose error patterns
        "SEVERE:",
        "WARNING:",
        "Stack Trace",
        "SEVERE: Exception",
        "WARNING: Exception",
        "Error loading WebappClassLoader",
        "Failed to deploy application",
        "Context initialization failed",
        "Tomcat Version",
        // Apache HTTP Server verbose error patterns
        "Server Error",
        "Apache Version",
        // Nginx web server verbose error patterns
        "upstream prematurely closed",
        "failed (111: Connection refused)",
        "error_page ",
        "server_name ",
        "client_max_body_size",
        "Nginx Version",
        // Common API verbose error patterns
        "Detailed Error Information",
        "Error Message",
        "Stack Trace",
        "Unhandled exception",
        "API Version",
        "Server: .*",
        "TemplateDoesNotExist",
        "Django"
    });
    
    }

    public List<int[]> geterrormessage(byte[] response) {

        List<int[]> allMatches = new ArrayList<>();
        for (String errorPattern : errorPatterns.get("Common")) {
            allMatches.addAll(getMatches_regex(response, errorPattern));
        }
        return allMatches;
    }

    public List<int[]> getSqlMatches(byte[] response) {
        List<int[]> allMatches = new ArrayList<>();
        for (String errorPattern : dbErrorPatterns.get("all")) {
            allMatches.addAll(getMatches(response, errorPattern.getBytes(), helper));
        }
        return allMatches;
    }

    public List<int[]> getMatches(byte[] response, byte[] match, IExtensionHelpers helper) {
        List<int[]> matches = new ArrayList<>();
        int start = 0;
        int resLen = response.length;
        int matchLen = match.length;

        while (start < resLen) {
            start = helper.indexOf(response, match, true, start, resLen);
            if (start == -1) {
                break;
            }
            int[] matchIndices = { start, start + matchLen };
            matches.add(matchIndices);
            start += matchLen;
        }

        return matches;
    }


    public static List<int[]> getMatches_regex(byte[] response, String regex) {
        List<int[]> matches = new ArrayList<>();

        Pattern pattern = Pattern.compile(regex);
        Matcher matcher = pattern.matcher(new String(response));

        while (matcher.find()) {
            int start = matcher.start();
            int end = matcher.end();
            int[] matchIndices = { start, end };
            matches.add(matchIndices);
        }

        return matches;
    }
}

