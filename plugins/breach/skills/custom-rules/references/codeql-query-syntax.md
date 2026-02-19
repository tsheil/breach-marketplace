# CodeQL Query Authoring Reference

Comprehensive reference for writing custom CodeQL queries. Covers query structure, taint tracking, language-specific models, custom predicates, path queries, and complete vulnerability detection examples.

## Query Structure

Every CodeQL query is a `.ql` file with a metadata block followed by QL code.

### Metadata Block

The metadata block is a QLDoc comment at the top of the file. All fields use `@` prefixed tags.

```ql
/**
 * @name SQL injection from user-controlled source
 * @description User input is concatenated into a SQL query without sanitization.
 * @kind path-problem
 * @id custom/sql-injection
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @tags security
 *       external/cwe/cwe-089
 *       external/owasp/owasp-a03
 */
```

#### Metadata Fields

| Field | Required | Description |
|-------|----------|-------------|
| `@name` | Yes | Human-readable query name. Keep concise. |
| `@description` | Yes | One-sentence description of what the query detects. |
| `@kind` | Yes | `problem` for alert queries, `path-problem` for dataflow path queries. |
| `@id` | Yes | Unique identifier. Use format `custom/<vuln-type>` or `custom/<language>/<vuln-type>`. |
| `@problem.severity` | Yes | `error`, `warning`, or `recommendation`. |
| `@security-severity` | No | CVSS score as a float (0.0-10.0). Determines severity in GitHub Code Scanning. |
| `@precision` | No | `very-high`, `high`, `medium`, or `low`. Indicates false positive rate. |
| `@tags` | No | Space-separated tags. Use `security` for security queries. CWE tags: `external/cwe/cwe-NNN`. |

#### @kind Values

- **`problem`** -- Alert queries. Report a single location per result. Use for pattern-matching queries that do not need to show a dataflow path.
- **`path-problem`** -- Path queries. Report a source-to-sink dataflow path. Use for taint tracking and dataflow queries.

### Import Statements

Import the language-specific library at the top of the query, after the metadata block.

```ql
import javascript    // JavaScript and TypeScript
import python        // Python
import java          // Java and Kotlin
import go            // Go
import csharp        // C#
import ruby          // Ruby
import cpp           // C and C++
import swift         // Swift
```

For taint tracking and dataflow queries, import the appropriate dataflow modules:

```ql
// JavaScript
import javascript
import DataFlow::PathGraph  // for path queries

// Python
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import DataFlow::PathGraph  // for path queries

// Java
import java
import semmle.code.java.dataflow.TaintTracking
import DataFlow::PathGraph  // for path queries

// Go
import go
import DataFlow::PathGraph  // for path queries
```

### from-where-select Pattern

All CodeQL queries use the `from ... where ... select` pattern:

```ql
from <variable declarations>
where <conditions>
select <result expressions>
```

**Alert query (`@kind problem`):**
```ql
from DataFlow::Node source, DataFlow::Node sink
where myTaintConfig(source, sink)
select sink, "User-controlled data flows to a dangerous sink."
```

The `select` clause for `@kind problem` must be: `select <element>, <message>`.

**Path query (`@kind path-problem`):**
```ql
from MyConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "User-controlled data from $@ flows to this sink.", source.getNode(), "user input"
```

The `select` clause for `@kind path-problem` must be: `select <sink element>, <source PathNode>, <sink PathNode>, <message>`.

## Taint Tracking Configuration

Taint tracking is CodeQL's mechanism for tracing potentially dangerous data from sources to sinks through program transformations.

### Modern API (CodeQL 2.x+)

The current recommended approach uses module-based configurations:

```ql
module MyConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    node instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node node) {
    // define sink conditions
  }

  predicate isBarrier(DataFlow::Node node) {
    // define sanitizers that stop taint propagation
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    // define additional taint steps not modeled by default
  }
}

module MyFlow = TaintTracking::Global<MyConfig>;
```

For path queries, also import the path graph:

```ql
import MyFlow::PathGraph

from MyFlow::PathNode source, MyFlow::PathNode sink
where MyFlow::flowPath(source, sink)
select sink.getNode(), source, sink, "Tainted data reaches this sink from $@.", source.getNode(), "here"
```

### Legacy API (class-based)

Older queries and some examples still use the class-based configuration. This is still functional but the module-based API is preferred.

```ql
class MyConfig extends TaintTracking::Configuration {
  MyConfig() { this = "MyConfig" }

  override predicate isSource(DataFlow::Node node) {
    node instanceof RemoteFlowSource
  }

  override predicate isSink(DataFlow::Node node) {
    // define sinks
  }

  override predicate isSanitizer(DataFlow::Node node) {
    // define sanitizers
  }

  override predicate isAdditionalTaintStep(DataFlow::Node node1, DataFlow::Node node2) {
    // define additional taint propagation steps
  }
}

from MyConfig config, DataFlow::PathNode source, DataFlow::PathNode sink
where config.hasFlowPath(source, sink)
select sink.getNode(), source, sink, "Tainted data reaches this sink."
```

### isSource Predicate

Defines where tainted data originates. The most common source is `RemoteFlowSource`, which captures HTTP request parameters, headers, body, cookies, and other remote input.

```ql
predicate isSource(DataFlow::Node node) {
  // All remote/user-controlled input
  node instanceof RemoteFlowSource
}
```

You can also define custom sources:

```ql
predicate isSource(DataFlow::Node node) {
  // Specific to reading environment variables
  exists(DataFlow::CallNode call |
    call.getCalleeName() = "getenv" and
    node = call
  )
}
```

### isSink Predicate

Defines dangerous operations where tainted data should not arrive unsanitized.

```ql
predicate isSink(DataFlow::Node node) {
  exists(DatabaseAccess da | node = da.getAnArgument())
}
```

### isBarrier / isSanitizer Predicate

Defines nodes that stop taint propagation. Essential for reducing false positives.

```ql
predicate isBarrier(DataFlow::Node node) {
  // Integer casts remove string-based injection risk
  node.getType() instanceof IntegerType
  or
  // Calls to known sanitization functions
  exists(DataFlow::CallNode call |
    call.getCalleeName() = ["escape", "sanitize", "encode", "parameterize"] and
    node = call
  )
}
```

### isAdditionalFlowStep / isAdditionalTaintStep Predicate

Defines additional taint propagation steps that the default model does not cover. Use this when taint should flow through custom functions, library calls, or framework-specific patterns.

```ql
predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
  // Taint propagates through JSON.parse
  exists(DataFlow::CallNode call |
    call.getCalleeName() = "parse" and
    call.getReceiver().getALocalSource().accessesGlobal("JSON") and
    node1 = call.getArgument(0) and
    node2 = call
  )
}
```

### Local vs Global Data Flow

- **Local data flow** (`DataFlow::localFlow`): Tracks data flow within a single function. Fast, limited scope. Use for simple pattern checks.
- **Global data flow** (`DataFlow::Global` / `TaintTracking::Global`): Tracks data flow across function boundaries, through call chains. Slower, comprehensive. Use for security vulnerability detection.

```ql
// Local flow -- within a single function
exists(DataFlow::Node source, DataFlow::Node sink |
  DataFlow::localFlow(source, sink) and
  source instanceof RemoteFlowSource and
  sink = someExpr.flow()
)

// Global flow -- across functions (use a configuration as shown above)
module MyFlow = TaintTracking::Global<MyConfig>;
```

## Language-Specific Models

### JavaScript / TypeScript

```ql
import javascript
```

#### Key Types

| Type | Description |
|------|-------------|
| `DataFlow::Node` | Any data flow node |
| `DataFlow::CallNode` | A function call |
| `DataFlow::FunctionNode` | A function definition |
| `DataFlow::ParameterNode` | A function parameter |
| `API::Node` | A node in the API graph (for modeling libraries) |
| `Expr` | An AST expression |
| `Function` | A function definition (AST) |

#### Common Sources

| Source Class | Description |
|--------------|-------------|
| `RemoteFlowSource` | All remote/HTTP input (params, headers, body, cookies) |
| `HTTP::RequestInputAccess` | Direct access to HTTP request properties |
| `ClientSideRemoteFlowSource` | Client-side user input (DOM, URL, etc.) |

```ql
// HTTP request parameter access in Express
exists(HTTP::RequestInputAccess input |
  input.getKind() = "parameter" and
  node = input
)

// Express route handler parameter
exists(Express::RouteHandler rh, DataFlow::ParameterNode param |
  param = rh.getRequestParameter() and
  node = param
)
```

#### Common Sinks

| Sink Class | Description |
|------------|-------------|
| `FileSystemAccess` | File read/write operations |
| `DatabaseAccess` | Database query execution |
| `SystemCommandExecution` | OS command execution |
| `SQL::SqlString` | String used as SQL |
| `CryptographicOperation` | Cryptographic operations |
| `ClientSideUrlRedirect` | Client-side redirect |

```ql
// Database query sink
exists(DatabaseAccess da | node = da.getAQueryArgument())

// Command execution sink
exists(SystemCommandExecution cmd | node = cmd.getACommandArgument())

// File system write
exists(FileSystemWriteAccess write | node = write.getADataNode())
```

#### Express / Node.js Patterns

```ql
// Express route handler with SQL injection
import javascript

module SqlInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    exists(Express::RouteHandler rh |
      node = rh.getARequestSource()
    )
  }

  predicate isSink(DataFlow::Node node) {
    exists(DatabaseAccess da | node = da.getAQueryArgument())
  }
}
```

#### API Graph for Library Modeling

The API graph provides a way to model library usage patterns:

```ql
// Model express().get() handler
API::Node express() {
  result = API::moduleImport("express").getReturn()
}

// Model a specific library function
API::Node dangerousFunction() {
  result = API::moduleImport("my-lib").getMember("dangerousMethod")
}
```

### Python

```ql
import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.Concepts
```

#### Key Types

| Type | Description |
|------|-------------|
| `DataFlow::Node` | Any data flow node |
| `DataFlow::CallCfgNode` | A function call |
| `DataFlow::CfgNode` | A control flow graph node |
| `RemoteFlowSource` | User-controlled remote input |
| `Expr` | An AST expression |
| `Call` | A function call (AST) |

#### Common Sources

| Source Class | Description |
|--------------|-------------|
| `RemoteFlowSource` | All remote flow sources (Flask request, Django request, etc.) |

```ql
// Flask request input
predicate isSource(DataFlow::Node node) {
  node instanceof RemoteFlowSource
}
```

#### Common Sinks

| Sink Concept | Description |
|--------------|-------------|
| `SqlExecution` | SQL query execution |
| `FileSystemAccess` | File system operations |
| `SystemCommandExecution` | OS command execution |
| `Decoding` | Deserialization operations |
| `CodeExecution` | Dynamic code execution (eval, exec) |
| `Http::Server::HttpResponse` | HTTP response body |

```ql
// SQL execution sink
predicate isSink(DataFlow::Node node) {
  exists(SqlExecution sqlExec | node = sqlExec.getSql())
}

// Command injection sink
predicate isSink(DataFlow::Node node) {
  exists(SystemCommandExecution cmd | node = cmd.getCommand())
}

// Code execution sink (eval/exec)
predicate isSink(DataFlow::Node node) {
  exists(CodeExecution exec | node = exec.getCode())
}
```

#### Flask Patterns

```ql
// Flask route handler receiving user input
import python
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.Concepts
import semmle.python.dataflow.new.TaintTracking

module FlaskSqlInjection implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    node instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node node) {
    exists(SqlExecution se | node = se.getSql())
  }

  predicate isBarrier(DataFlow::Node node) {
    // Parameterized queries handled by the library model
    none()
  }
}

module FlaskSqlInjectionFlow = TaintTracking::Global<FlaskSqlInjection>;
```

#### Django Patterns

```ql
// Django ORM raw query usage
predicate isDjangoRawSqlSink(DataFlow::Node node) {
  exists(DataFlow::CallCfgNode call |
    call.getFunction().toString().matches("%raw%") and
    node = call.getArg(0)
  )
}
```

### Java

```ql
import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.QueryInjection
import semmle.code.java.security.CommandLineQuery
```

#### Key Types

| Type | Description |
|------|-------------|
| `DataFlow::Node` | Any data flow node |
| `RemoteFlowSource` | Remote user input (servlet, Spring, etc.) |
| `Method` | A method declaration |
| `MethodCall` | A method invocation |
| `Expr` | An AST expression |
| `Class` | A class declaration |

#### Common Sources

| Source Class | Description |
|--------------|-------------|
| `RemoteFlowSource` | HTTP request parameters, headers, body via servlet/Spring |
| `EnvInput` | Environment variables and system properties |

```ql
predicate isSource(DataFlow::Node node) {
  node instanceof RemoteFlowSource
}

// Specifically servlet request parameters
predicate isSource(DataFlow::Node node) {
  exists(MethodCall ma |
    ma.getMethod().getName() = ["getParameter", "getHeader", "getQueryString"] and
    ma.getMethod().getDeclaringType().getASupertype*().hasQualifiedName("javax.servlet.http", "HttpServletRequest") and
    node.asExpr() = ma
  )
}
```

#### Common Sinks

| Sink Class | Description |
|------------|-------------|
| `QueryInjectionSink` | SQL/NoSQL query execution |
| `CommandInjectionSink` | OS command execution |
| `XssSink` | Cross-site scripting output |
| `UrlRedirectSink` | HTTP redirect with user input |
| `XxeSink` | XML parsing with external entities |

```ql
// SQL injection sink
predicate isSink(DataFlow::Node node) {
  node instanceof QueryInjectionSink
}

// Command injection sink
predicate isSink(DataFlow::Node node) {
  exists(MethodCall ma |
    ma.getMethod().hasName("exec") and
    ma.getMethod().getDeclaringType().hasQualifiedName("java.lang", "Runtime") and
    node.asExpr() = ma.getArgument(0)
  )
}
```

#### Spring Patterns

```ql
// Spring controller parameter as source
predicate isSource(DataFlow::Node node) {
  exists(Parameter p, Annotation a |
    a = p.getAnAnnotation() and
    a.getType().hasQualifiedName("org.springframework.web.bind.annotation", ["RequestParam", "PathVariable", "RequestBody", "RequestHeader"]) and
    node.asParameter() = p
  )
}

// Spring JdbcTemplate query sink
predicate isSink(DataFlow::Node node) {
  exists(MethodCall ma |
    ma.getMethod().getDeclaringType().hasQualifiedName("org.springframework.jdbc.core", "JdbcTemplate") and
    ma.getMethod().hasName(["query", "queryForList", "queryForMap", "queryForObject", "execute", "update"]) and
    node.asExpr() = ma.getArgument(0)
  )
}
```

### Go

```ql
import go
```

#### Key Types

| Type | Description |
|------|-------------|
| `DataFlow::Node` | Any data flow node |
| `UntrustedFlowSource` | Remote/untrusted input |
| `Function` | A function declaration |
| `CallExpr` | A function call expression |
| `FuncDecl` | A function declaration |

#### Common Sources

| Source Class | Description |
|--------------|-------------|
| `UntrustedFlowSource` | HTTP request parameters, headers, body |
| `RemoteFlowSource` | Alias; remote flow sources |

```ql
predicate isSource(DataFlow::Node node) {
  node instanceof UntrustedFlowSource
}

// net/http request specifically
predicate isSource(DataFlow::Node node) {
  exists(DataFlow::CallNode call |
    call.getTarget().hasQualifiedName("net/http", "Request", ["FormValue", "URL.Query"]) and
    node = call.getResult()
  )
}
```

#### Common Sinks

| Sink Concept | Description |
|--------------|-------------|
| `SQL::QueryString` | SQL query string |
| `SystemCommandExecution` | OS command execution |
| `FileSystemAccess` | File operations |
| `Http::Redirect` | HTTP redirect |

```ql
// SQL injection sink
predicate isSink(DataFlow::Node node) {
  exists(SQL::QueryString qs | node = qs)
}

// Command injection sink
predicate isSink(DataFlow::Node node) {
  exists(SystemCommandExecution cmd | node = cmd.getCommandName())
}

// os/exec.Command argument
predicate isSink(DataFlow::Node node) {
  exists(DataFlow::CallNode call |
    call.getTarget().hasQualifiedName("os/exec", "Command") and
    node = call.getAnArgument()
  )
}
```

#### net/http Patterns

```ql
// Handler function receiving request
predicate isHttpHandler(Function f) {
  f.getAParameter().getType().hasQualifiedName("net/http", "ResponseWriter") and
  f.getAParameter().getType().(PointerType).getBaseType().hasQualifiedName("net/http", "Request")
}
```

## Common Source/Sink Predicates by Language

### Sources Summary

| Language | Primary Source | Import |
|----------|---------------|--------|
| JavaScript | `RemoteFlowSource` | `import javascript` |
| Python | `RemoteFlowSource` | `import semmle.python.dataflow.new.RemoteFlowSources` |
| Java | `RemoteFlowSource` | `import semmle.code.java.dataflow.FlowSources` |
| Go | `UntrustedFlowSource` | `import go` |

### Sinks Summary

| Vulnerability | JavaScript | Python | Java | Go |
|--------------|------------|--------|------|-----|
| SQL Injection | `DatabaseAccess.getAQueryArgument()` | `SqlExecution.getSql()` | `QueryInjectionSink` | `SQL::QueryString` |
| Command Injection | `SystemCommandExecution.getACommandArgument()` | `SystemCommandExecution.getCommand()` | `CommandInjectionSink` | `SystemCommandExecution.getCommandName()` |
| XSS | `DomBasedXss::Sink` | `Http::Server::HttpResponse.getBody()` | `XssSink` | `Http::ResponseBody` |
| Path Traversal | `FileSystemAccess.getAPathArgument()` | `FileSystemAccess.getAPathArgument()` | `PathInjectionSink` | `FileSystemAccess.getAPathArgument()` |
| SSRF | `ClientRequest.getUrl()` | `Http::Client::Request.getURL()` | `RequestForgerySink` | `Http::ClientRequest.getUrl()` |
| Open Redirect | `ServerSideUrlRedirect` | `Http::Server::HttpRedirectResponse.getRedirectUrl()` | `UrlRedirectSink` | `Http::Redirect.getUrl()` |

### Defining Custom Sources

When the built-in source classes are insufficient, define custom sources by matching specific API calls:

```ql
// Custom source: reading from a message queue
predicate isSource(DataFlow::Node node) {
  exists(DataFlow::CallNode call |
    call.getCalleeName() = ["receive", "consume", "poll"] and
    call.getReceiver().getALocalSource().getAPropertyRead().getPropertyName() = "queue" and
    node = call
  )
}
```

### Defining Custom Sinks

```ql
// Custom sink: writing to a response template
predicate isSink(DataFlow::Node node) {
  exists(DataFlow::CallNode call |
    call.getCalleeName() = ["render", "renderTemplate", "renderString"] and
    node = call.getAnArgument()
  )
}
```

## Custom Predicates

### Defining Helper Predicates

Predicates are reusable conditions. They can return boolean (no result columns) or bind variables (with result columns).

```ql
// Boolean predicate (characteristic predicate)
predicate isAuthEndpoint(Function f) {
  f.getName().regexpMatch("(?i).*(login|auth|register|signup|password|token).*")
}

// Predicate with result
DataFlow::Node getADatabaseArgument() {
  exists(DatabaseAccess da | result = da.getAQueryArgument())
}

// Predicate with parameters and result
string getHttpMethod(Express::RouteHandler rh) {
  exists(Express::RouteSetup setup |
    setup.getARouteHandler() = rh and
    result = setup.getHttpMethod()
  )
}
```

### Recursive Predicates

Predicates can be recursive to model transitive relationships:

```ql
// Find all functions reachable from a given function through call chains
predicate callsTransitive(Function caller, Function callee) {
  caller.getACallee() = callee
  or
  exists(Function mid |
    caller.getACallee() = mid and
    callsTransitive(mid, callee)
  )
}

// Using transitive closure operator (preferred for simple cases)
predicate callsTransitive(Function caller, Function callee) {
  caller.getACallee+() = callee   // + is the transitive closure
}
```

### Quantifiers: exists() and forall()

```ql
// exists: "there exists" -- true if at least one binding satisfies the condition
exists(DataFlow::CallNode call |
  call.getCalleeName() = "eval" and
  node = call.getArgument(0)
)

// forall: "for all" -- true if every binding satisfies the condition
// Rarely used in security queries. Example: all parameters are validated.
forall(Parameter p |
  p = func.getAParameter() |
  isValidated(p)
)

// not exists: negation
not exists(SanitizationCall sc | sc.sanitizes(node))

// Combining: "no calls to validate exist in this function"
not exists(DataFlow::CallNode call |
  call.getCalleeName() = "validate" and
  call.getEnclosingFunction() = func
)
```

### Aggregate Functions

```ql
// count: number of matching bindings
count(Parameter p | p = func.getAParameter())

// sum, min, max: numeric aggregation
max(int line | exists(Expr e | e.getLocation().getStartLine() = line and e.getEnclosingFunction() = func) | line)

// Aggregates in conditions
where count(Parameter p | p = func.getAParameter()) > 5
```

### String Predicates

```ql
// regexpMatch: full string regex match
name.regexpMatch("(?i).*password.*")

// matches: glob-style pattern matching (% is wildcard)
name.matches("%password%")
name.matches("get%")

// Other string operations
str.indexOf("secret") >= 0
str.prefix(4) = "http"
str.suffix(3) = ".js"
str.length() > 100
str.toLowerCase() = "admin"
str.splitAt("/", 2) = "api"
str.replaceAll("'", "''")
```

## Path Queries

Path queries show the full dataflow path from source to sink in results, which is critical for security analysis because it demonstrates exploitability.

### Full Path Query Structure

```ql
/**
 * @name Custom taint tracking query
 * @description Detects tainted data flowing from source to sink.
 * @kind path-problem
 * @id custom/my-taint-query
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @tags security
 */

import javascript
// Define the configuration
module MyTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    node instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node node) {
    exists(DatabaseAccess da | node = da.getAQueryArgument())
  }

  predicate isBarrier(DataFlow::Node node) {
    node.getType().toString() = "number"
  }
}

module MyTaintFlow = TaintTracking::Global<MyTaintConfig>;

// Import the path graph for visualization
import MyTaintFlow::PathGraph

from MyTaintFlow::PathNode source, MyTaintFlow::PathNode sink
where MyTaintFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Tainted data from $@ reaches this database query.", source.getNode(), "user input"
```

### The select Clause for Path Queries

The `select` clause must follow this exact format for `@kind path-problem`:

```
select <element>, <source PathNode>, <sink PathNode>, <message>, [<link target>, <link text>]*
```

- `<element>` -- The AST node to highlight in results (usually `sink.getNode()`).
- `<source PathNode>` -- The `PathNode` representing the source.
- `<sink PathNode>` -- The `PathNode` representing the sink.
- `<message>` -- Description string. Use `$@` as a placeholder for linked elements.
- `<link target>, <link text>` -- Pairs that replace each `$@` in the message.

### edges Predicate

The `edges` predicate is automatically provided when you import a `PathGraph` module. You do not need to define it manually unless customizing path display.

```ql
// Standard usage -- just import the PathGraph
import MyTaintFlow::PathGraph

// Custom edges (advanced, rarely needed)
predicate edges(MyTaintFlow::PathNode pred, MyTaintFlow::PathNode succ) {
  MyTaintFlow::PathGraph::edges(pred, succ)
}
```

## Complete Examples

### SQL Injection -- JavaScript (Express + any database)

```ql
/**
 * @name SQL injection in Express application
 * @description User input from HTTP requests is used in a SQL query without parameterization.
 * @kind path-problem
 * @id custom/js/sql-injection
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @tags security
 *       external/cwe/cwe-089
 */

import javascript

module SqlInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    node instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node node) {
    exists(DatabaseAccess da | node = da.getAQueryArgument())
  }

  predicate isBarrier(DataFlow::Node node) {
    // Integer conversion sanitizes string injection
    node instanceof DataFlow::CallNode and
    node.(DataFlow::CallNode).getCalleeName() = ["parseInt", "parseFloat", "Number"]
  }
}

module SqlInjectionFlow = TaintTracking::Global<SqlInjectionConfig>;
import SqlInjectionFlow::PathGraph

from SqlInjectionFlow::PathNode source, SqlInjectionFlow::PathNode sink
where SqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This SQL query depends on $@.", source.getNode(), "user-provided input"
```

### SQL Injection -- Python (Flask + raw SQL)

```ql
/**
 * @name SQL injection in Python application
 * @description User input flows into a SQL query without parameterization.
 * @kind path-problem
 * @id custom/py/sql-injection
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @tags security
 *       external/cwe/cwe-089
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.dataflow.new.RemoteFlowSources
import semmle.python.Concepts

module PySqlInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    node instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node node) {
    exists(SqlExecution se | node = se.getSql())
  }

  predicate isBarrier(DataFlow::Node node) {
    // Int conversion removes string injection risk
    exists(DataFlow::CallCfgNode call |
      call.getFunction().toString() = "int" and
      node = call
    )
  }
}

module PySqlInjectionFlow = TaintTracking::Global<PySqlInjectionConfig>;
import PySqlInjectionFlow::PathGraph

from PySqlInjectionFlow::PathNode source, PySqlInjectionFlow::PathNode sink
where PySqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This SQL query depends on $@.", source.getNode(), "user-provided input"
```

### SQL Injection -- Java (Spring + JDBC)

```ql
/**
 * @name SQL injection in Java application
 * @description User input is concatenated into a SQL query string.
 * @kind path-problem
 * @id custom/java/sql-injection
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @tags security
 *       external/cwe/cwe-089
 */

import java
import semmle.code.java.dataflow.TaintTracking
import semmle.code.java.dataflow.FlowSources
import semmle.code.java.security.QueryInjection

module JavaSqlInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    node instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node node) {
    node instanceof QueryInjectionSink
  }

  predicate isBarrier(DataFlow::Node node) {
    // PreparedStatement parameterization is modeled by the library
    none()
  }
}

module JavaSqlInjectionFlow = TaintTracking::Global<JavaSqlInjectionConfig>;
import JavaSqlInjectionFlow::PathGraph

from JavaSqlInjectionFlow::PathNode source, JavaSqlInjectionFlow::PathNode sink
where JavaSqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This SQL query depends on $@.", source.getNode(), "user-provided input"
```

### SQL Injection -- Go

```ql
/**
 * @name SQL injection in Go application
 * @description User input is interpolated into a SQL query string.
 * @kind path-problem
 * @id custom/go/sql-injection
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @tags security
 *       external/cwe/cwe-089
 */

import go

module GoSqlInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    node instanceof UntrustedFlowSource
  }

  predicate isSink(DataFlow::Node node) {
    exists(SQL::QueryString qs | node = qs)
  }
}

module GoSqlInjectionFlow = TaintTracking::Global<GoSqlInjectionConfig>;
import GoSqlInjectionFlow::PathGraph

from GoSqlInjectionFlow::PathNode source, GoSqlInjectionFlow::PathNode sink
where GoSqlInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This SQL query depends on $@.", source.getNode(), "untrusted input"
```

### Command Injection -- JavaScript

```ql
/**
 * @name Command injection
 * @description User input flows into an OS command execution call.
 * @kind path-problem
 * @id custom/js/command-injection
 * @problem.severity error
 * @security-severity 9.8
 * @precision high
 * @tags security
 *       external/cwe/cwe-078
 */

import javascript

module CmdInjectionConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    node instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node node) {
    exists(SystemCommandExecution cmd | node = cmd.getACommandArgument())
  }

  predicate isBarrier(DataFlow::Node node) {
    // Allow-list validation stops injection
    exists(DataFlow::CallNode call |
      call.getCalleeName() = ["includes", "indexOf", "match"] and
      node = call.getReceiver()
    )
  }
}

module CmdInjectionFlow = TaintTracking::Global<CmdInjectionConfig>;
import CmdInjectionFlow::PathGraph

from CmdInjectionFlow::PathNode source, CmdInjectionFlow::PathNode sink
where CmdInjectionFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "This OS command depends on $@.", source.getNode(), "user-provided input"
```

### Missing Authorization Check -- JavaScript (Alert Query)

```ql
/**
 * @name Missing authorization check on sensitive endpoint
 * @description A route handler accesses sensitive data without calling an authorization function.
 * @kind problem
 * @id custom/js/missing-auth-check
 * @problem.severity warning
 * @security-severity 7.5
 * @precision medium
 * @tags security
 *       external/cwe/cwe-862
 */

import javascript

/** A route handler that accesses a sensitive resource. */
predicate isSensitiveHandler(Express::RouteHandler handler) {
  exists(DatabaseAccess da |
    da.getEnclosingFunction() = handler.getFunction()
  )
  or
  exists(FileSystemAccess fa |
    fa.getEnclosingFunction() = handler.getFunction()
  )
}

/** Whether a function calls an authorization check. */
predicate hasAuthCheck(Function f) {
  exists(DataFlow::CallNode call |
    call.getCalleeName().regexpMatch("(?i).*(auth|authorize|checkPermission|isAdmin|requireLogin|ensureAuth|verifyToken|isAuthenticated).*") and
    call.getEnclosingFunction() = f
  )
}

/** Whether a route uses auth middleware. */
predicate hasAuthMiddleware(Express::RouteSetup setup) {
  exists(DataFlow::Node middleware |
    middleware = setup.getAMiddlewareExpr().flow() and
    middleware.getALocalSource().toString().regexpMatch("(?i).*(auth|passport|jwt|session|protect|guard).*")
  )
}

from Express::RouteHandler handler, Express::RouteSetup setup
where
  setup.getARouteHandler() = handler and
  isSensitiveHandler(handler) and
  not hasAuthCheck(handler.getFunction()) and
  not hasAuthMiddleware(setup)
select handler,
  "This route handler accesses sensitive resources but has no authorization check or middleware."
```

### Cross-Site Scripting (XSS) -- JavaScript

```ql
/**
 * @name Reflected cross-site scripting
 * @description User input is included in the HTTP response body without escaping.
 * @kind path-problem
 * @id custom/js/reflected-xss
 * @problem.severity error
 * @security-severity 6.1
 * @precision high
 * @tags security
 *       external/cwe/cwe-079
 */

import javascript

module XssConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    node instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node node) {
    // res.send(), res.write(), or template rendering with unescaped output
    exists(HTTP::ResponseSendArgument send | node = send)
    or
    exists(DataFlow::CallNode call |
      call.getCalleeName() = ["send", "write", "end", "render"] and
      node = call.getAnArgument()
    )
  }

  predicate isBarrier(DataFlow::Node node) {
    // HTML encoding/escaping functions
    exists(DataFlow::CallNode call |
      call.getCalleeName() = ["escape", "encode", "escapeHtml", "sanitize", "encodeURIComponent", "htmlEncode"] and
      node = call
    )
    or
    // JSON.stringify removes HTML context risk
    exists(DataFlow::CallNode call |
      call.getCalleeName() = "stringify" and
      node = call
    )
  }
}

module XssFlow = TaintTracking::Global<XssConfig>;
import XssFlow::PathGraph

from XssFlow::PathNode source, XssFlow::PathNode sink
where XssFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Cross-site scripting vulnerability due to $@.", source.getNode(), "user-provided input"
```

### Custom Taint Tracking -- Tracking Through Framework-Specific Methods

This example shows how to add taint steps for a custom ORM where data flows through model methods:

```ql
/**
 * @name Taint through custom ORM
 * @description Tracks taint through a custom ORM's query builder methods.
 * @kind path-problem
 * @id custom/js/orm-taint
 * @problem.severity error
 * @security-severity 8.0
 * @precision high
 * @tags security
 */

import javascript

module OrmTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    node instanceof RemoteFlowSource
  }

  predicate isSink(DataFlow::Node node) {
    // The ORM's .execute() or .run() sends the query to the database
    exists(DataFlow::CallNode call |
      call.getCalleeName() = ["execute", "run", "exec"] and
      node = call.getReceiver()
    )
  }

  predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
    // Taint flows through chained query builder methods:
    // db.where(userInput).orderBy(...) -- taint stays on the builder
    exists(DataFlow::CallNode call |
      call.getCalleeName() = ["where", "filter", "having", "orderBy", "groupBy", "join", "select", "raw"] and
      (
        // Taint from argument into the return value (chaining)
        node1 = call.getAnArgument() and node2 = call
        or
        // Taint from receiver through to the return value (chaining)
        node1 = call.getReceiver() and node2 = call
      )
    )
  }
}

module OrmTaintFlow = TaintTracking::Global<OrmTaintConfig>;
import OrmTaintFlow::PathGraph

from OrmTaintFlow::PathNode source, OrmTaintFlow::PathNode sink
where OrmTaintFlow::flowPath(source, sink)
select sink.getNode(), source, sink,
  "Tainted data from $@ flows through ORM methods to query execution.", source.getNode(), "user input"
```

## Common Pitfalls

### 1. Missing Taint Steps for Framework-Specific Data Flow

**Problem**: CodeQL's built-in models do not cover every library and framework. Taint may be "lost" when data passes through an unmodeled function, causing false negatives.

**Symptom**: You know a vulnerability exists but CodeQL reports no results.

**Fix**: Add `isAdditionalFlowStep` to propagate taint through unmodeled functions:

```ql
predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
  exists(DataFlow::CallNode call |
    call.getCalleeName() = "myFrameworkMethod" and
    node1 = call.getArgument(0) and
    node2 = call
  )
}
```

### 2. Overly Broad Source Definitions

**Problem**: Using `RemoteFlowSource` captures all remote input, but some sources may not be attacker-controlled in context (e.g., trusted internal APIs, authenticated admin-only endpoints).

**Symptom**: Many false positive results from data flows that start at trusted sources.

**Fix**: Narrow the source definition to specific entry points, or add a barrier for trusted contexts:

```ql
predicate isSource(DataFlow::Node node) {
  node instanceof RemoteFlowSource and
  // Only consider sources in public-facing route handlers
  not exists(Express::RouteHandler rh |
    node.getEnclosingFunction() = rh.getFunction() and
    isInternalOnly(rh)
  )
}
```

### 3. Overly Broad Sink Definitions

**Problem**: A sink predicate matches operations that are not actually dangerous, or matches parameterized/safe variants along with dangerous ones.

**Symptom**: Results point to code that is already using safe APIs (parameterized queries, prepared statements).

**Fix**: Make sinks more specific. Exclude safe API usage patterns:

```ql
predicate isSink(DataFlow::Node node) {
  exists(DataFlow::CallNode call |
    call.getCalleeName() = "query" and
    node = call.getArgument(0) and
    // Exclude parameterized calls (2+ arguments = parameterized)
    not call.getNumArgument() >= 2
  )
}
```

### 4. Missing Sanitizer Definitions

**Problem**: Without sanitizers, CodeQL reports taint paths that pass through validation, escaping, or encoding functions, producing false positives.

**Symptom**: Results show taint flowing through functions like `escapeHtml()`, `parseInt()`, or validation middleware.

**Fix**: Add `isBarrier` for known sanitization patterns:

```ql
predicate isBarrier(DataFlow::Node node) {
  // Type conversion sanitizers
  exists(DataFlow::CallNode call |
    call.getCalleeName() = ["parseInt", "parseFloat", "Number", "Boolean"] and
    node = call
  )
  or
  // Encoding/escaping sanitizers
  exists(DataFlow::CallNode call |
    call.getCalleeName() = ["escape", "escapeHtml", "encodeURIComponent", "sanitize", "DOMPurify.sanitize"] and
    node = call
  )
  or
  // Validation that throws on invalid input
  exists(DataFlow::CallNode call |
    call.getCalleeName() = ["validate", "assert", "check"] and
    node = call
  )
}
```

### 5. Not Handling Language-Specific Type Systems

**Problem**: Each language has different type system semantics that affect how taint propagates. Java's type casts, Go's interfaces, Python's dynamic typing, and TypeScript's type narrowing all behave differently.

**Symptom**: Taint tracking produces inconsistent results across languages, or misses flows through type conversions.

**Fix**: Account for language-specific patterns:

```ql
// Java: taint through type casts
predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
  exists(CastExpr cast |
    node1.asExpr() = cast.getExpr() and
    node2.asExpr() = cast
  )
}

// Go: taint through interface conversions
predicate isAdditionalFlowStep(DataFlow::Node node1, DataFlow::Node node2) {
  exists(TypeAssertExpr ta |
    node1.asExpr() = ta.getExpr() and
    node2.asExpr() = ta
  )
}
```

### 6. Using @kind problem When @kind path-problem Is Needed

**Problem**: Using `@kind problem` for taint tracking queries loses the dataflow path information, making results harder to verify and less actionable.

**Fix**: Always use `@kind path-problem` with `DataFlow::PathGraph` for taint tracking queries. Use `@kind problem` only for simple pattern-matching queries that do not involve dataflow.

### 7. Incorrect select Clause Format

**Problem**: The `select` clause format differs between `@kind problem` and `@kind path-problem`. Using the wrong format produces errors.

**Fix**:

```ql
// @kind problem -- two elements: location and message
select element, "Message about the problem."

// @kind path-problem -- source and sink PathNodes plus message
select sink.getNode(), source, sink, "Message with $@ link.", source.getNode(), "link text"
```

### 8. Performance Issues with Large Codebases

**Problem**: Complex recursive predicates or broad joins can cause queries to time out on large codebases.

**Fix**:
- Add type constraints to narrow variable bindings early in the `where` clause.
- Use `pragma[nomagic]` on helper predicates to control join ordering.
- Limit path length with `hasFlowPath` configuration options.
- Test queries on small codebases first before running on large targets.

```ql
// Use pragma to prevent the optimizer from inlining
pragma[nomagic]
predicate myHelperPredicate(DataFlow::Node node) {
  // expensive computation
}
```
