# GraphQL Security Patterns

GraphQL introduces a unique attack surface distinct from REST APIs. Its single-endpoint architecture, self-documenting schema, query flexibility, and client-driven data fetching create security challenges that traditional API security measures often fail to address. Vulnerabilities in GraphQL implementations frequently stem from the assumption that the query language itself provides security boundaries, when in practice authorization, rate limiting, and input validation must be enforced at the resolver level.

## Key Patterns to Search For

Search for these patterns in the codebase to identify potential GraphQL security issues:

- **Introspection enabled in production**: `introspection: true`, `__schema`, `__type`, missing introspection disable in production config
- **Missing resolver-level authorization (IDOR via GraphQL)**: Resolvers that query the database directly using client-supplied arguments without ownership or permission checks
- **Batching attacks (brute force bypass)**: Array of operations in a single request, `batching: true`, `allowBatchedQueries`, no per-operation rate limiting
- **Nested query DoS (depth/complexity limits missing)**: Absence of `depthLimit`, `costAnalysis`, `queryComplexity`, `validationRules` in server configuration
- **Field-level access control gaps**: Sensitive fields (`email`, `password`, `ssn`, `token`, `secret`, `role`, `internalId`) exposed without field-level auth directives
- **GraphQL injection (server-to-server)**: String interpolation in GraphQL query construction: `` `query { user(id: "${id}") }` ``, `"query { ... " + userInput + " ... }"`
- **Subscription authorization bypass**: `subscription` resolvers missing auth checks, WebSocket `connection_init` without token validation
- **Alias-based rate limit bypass**: No per-operation or per-field rate limiting, rate limits applied only at the HTTP request level
- **Schema Definition Language (SDL) exposure**: `/graphql/schema`, `/graphql/sdl`, `printSchema()` accessible in production
- **Debug and error information leakage**: `debug: true`, `formatError` returning stack traces or internal paths, `extensions` exposing query plans

## Common Vulnerable Patterns

**Introspection Enabled in Production:**
```javascript
// Vulnerable: introspection left enabled in production
const server = new ApolloServer({
  typeDefs,
  resolvers,
  // No introspection setting — defaults to enabled
  // Attacker can query __schema to map every type, field, and mutation
});
```

```graphql
# Attacker's introspection query to enumerate the full schema
{
  __schema {
    types {
      name
      fields {
        name
        type { name kind }
        args { name type { name } }
      }
    }
    mutationType {
      fields { name }
    }
  }
}
```

Why it is dangerous: Full schema introspection reveals every query, mutation, subscription, type, and field — including internal or administrative endpoints the developer assumed would remain undiscovered. This is the equivalent of handing an attacker a complete API specification.

**Resolver Without Authorization Check (IDOR):**
```javascript
// Vulnerable: resolver fetches any user by ID without verifying
// that the requesting user has permission to access that record
const resolvers = {
  Query: {
    user: async (_, { id }, context) => {
      // No check: context.user.id === id or context.user.role === 'admin'
      return db.users.findById(id);
    },
    order: async (_, { orderId }) => {
      // No context parameter used at all — completely unauthenticated
      return db.orders.findById(orderId);
    },
  },
};
```

```python
# Vulnerable: Graphene resolver with no authorization
class Query(graphene.ObjectType):
    user = graphene.Field(UserType, id=graphene.ID(required=True))

    def resolve_user(self, info, id):
        # No check against info.context.user
        # Any authenticated (or unauthenticated) user can fetch any user record
        return User.objects.get(pk=id)
```

Why it is dangerous: This is a classic IDOR vulnerability exposed through GraphQL. An attacker can enumerate user IDs and retrieve any user's data. The GraphQL layer provides no implicit authorization — every resolver must enforce its own access control.

**Batched Login Mutation (Brute Force Bypass):**
```graphql
# Attacker sends a single HTTP request containing hundreds of login attempts
# Each aliased mutation is a separate brute force attempt
# Per-request rate limiting sees only 1 request, not 500 attempts
mutation {
  attempt1: login(username: "admin", password: "password1") { token }
  attempt2: login(username: "admin", password: "password2") { token }
  attempt3: login(username: "admin", password: "password3") { token }
  # ... repeat for hundreds of passwords
  attempt500: login(username: "admin", password: "password500") { token }
}
```

```javascript
// Vulnerable: server processes batched mutations without per-operation limiting
const server = new ApolloServer({
  typeDefs,
  resolvers,
  // No plugin or middleware to count operations within a single request
  // Rate limiter only counts HTTP requests, not individual operations
});

// Rate limiting middleware that does not account for batching
app.use('/graphql', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100, // 100 requests per 15 minutes — but each request has 500 mutations
}));
```

Why it is dangerous: A single HTTP request can contain hundreds of aliased mutations, each executing a login attempt. Standard rate limiting counts HTTP requests, not GraphQL operations. An attacker can attempt thousands of passwords within the rate limit window.

**Deeply Nested Query Without Depth Limiting:**
```graphql
# Recursive relationship exploited for resource exhaustion
# If User has friends (also Users), the query can nest indefinitely
{
  user(id: "1") {
    friends {
      friends {
        friends {
          friends {
            friends {
              friends {
                friends {
                  friends {
                    friends {
                      friends {
                        id
                        email
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}
```

```javascript
// Vulnerable: no depth or complexity limits configured
const server = new ApolloServer({
  typeDefs,
  resolvers,
  // Missing: validationRules with depthLimit or costAnalysis
  // A single query can trigger exponential database lookups
});
```

Why it is dangerous: Recursive type relationships (users with friends, comments with replies, categories with subcategories) allow attackers to craft queries that trigger exponential server-side processing. A depth of 10 on a relationship where each node has 10 children causes 10 billion potential resolutions.

**Field Returning Sensitive Data Without Field-Level Auth:**
```javascript
// Vulnerable: User type exposes sensitive fields to any requester
const typeDefs = gql`
  type User {
    id: ID!
    username: String!
    email: String!
    role: String!
    passwordHash: String!    # Sensitive: should never be exposed
    ssn: String              # Sensitive: requires elevated access
    internalNotes: String    # Sensitive: admin-only field
    apiKey: String           # Sensitive: credential
  }
`;

const resolvers = {
  Query: {
    user: async (_, { id }, context) => {
      // Even if the query-level resolver checks auth,
      // ALL fields are returned if the user object is returned whole
      if (!context.user) throw new AuthenticationError('Not authenticated');
      return db.users.findById(id); // Returns entire user object including passwordHash
    },
  },
};
```

```python
# Vulnerable: Graphene type exposes all model fields
class UserType(DjangoObjectType):
    class Meta:
        model = User
        fields = '__all__'  # Exposes every field on the Django model
        # Including: password, is_superuser, last_login, internal fields
```

Why it is dangerous: GraphQL allows clients to select exactly which fields they want. If sensitive fields exist on a type, any client can request them. Returning the full database object from a resolver exposes every field on the type, and developers often overlook that clients can query fields they did not intend to expose.

**Alias-Based Rate Limit Bypass:**
```graphql
# Each alias executes the resolver separately, but it is a single query
# Rate limiting at the query level sees one query, not 100 resolver executions
query {
  q1: sensitiveSearch(term: "a") { results { id data } }
  q2: sensitiveSearch(term: "b") { results { id data } }
  q3: sensitiveSearch(term: "c") { results { id data } }
  q4: sensitiveSearch(term: "d") { results { id data } }
  # ... 100 aliased calls to the same expensive resolver
  q100: sensitiveSearch(term: "zz") { results { id data } }
}
```

Why it is dangerous: Aliases allow the same field or query to be executed multiple times within a single GraphQL operation. This bypasses rate limiting applied at the HTTP request or query-operation level. Expensive resolvers (search, external API calls, database aggregations) can be invoked hundreds of times in one request.

**GraphQL Injection in Server-to-Server Queries:**
```javascript
// Vulnerable: constructing a GraphQL query via string interpolation
// Used when one service queries another service's GraphQL API
async function getUserFromService(userId) {
  const query = `
    query {
      user(id: "${userId}") {
        id
        name
        email
      }
    }
  `;
  // If userId is: ") { id } } mutation { deleteUser(id: "1
  // the query structure is altered
  return fetch('http://internal-graphql/graphql', {
    method: 'POST',
    body: JSON.stringify({ query }),
  });
}
```

Why it is dangerous: When services construct GraphQL queries via string interpolation, an attacker who controls the interpolated value can inject additional queries or mutations. This is analogous to SQL injection but targets the GraphQL query language.

```python
# Vulnerable: Python service constructing GraphQL query with f-string
import requests

def fetch_product(product_id: str) -> dict:
    query = f'''
        query {{
            product(id: "{product_id}") {{
                id
                name
                price
            }}
        }}
    '''
    # If product_id is: ") { id } } mutation { deleteProduct(id: "1
    # the injected payload restructures the entire query
    response = requests.post(
        'http://product-service:4000/graphql',
        json={'query': query}
    )
    return response.json()
```

Why it is dangerous: Python f-strings and format strings are commonly used in microservice architectures to construct GraphQL queries. The double-brace escaping required for GraphQL syntax within f-strings makes the code harder to read and review, increasing the likelihood that injection vulnerabilities go unnoticed during code review.

**Subscription Authorization Bypass:**
```javascript
// Vulnerable: subscription resolver does not verify authorization
const resolvers = {
  Subscription: {
    orderUpdated: {
      subscribe: (_, { orderId }, context) => {
        // No check: does context.user own this order?
        // Any authenticated user can subscribe to any order's updates
        return pubsub.asyncIterator(`ORDER_${orderId}`);
      },
    },
    adminNotifications: {
      subscribe: (_, __, context) => {
        // No check: is context.user an admin?
        return pubsub.asyncIterator('ADMIN_NOTIFICATIONS');
      },
    },
  },
};
```

Why it is dangerous: Subscriptions maintain long-lived WebSocket connections. If authorization is only checked at connection time and not per-subscription, any authenticated user can subscribe to events they should not have access to, receiving real-time updates on other users' data.

## Exploitability Indicators

A GraphQL security finding is exploitable (not merely theoretical) when:

- **Introspection**: The `/graphql` endpoint responds to `__schema` queries in a production environment, revealing types, mutations, and fields that are not documented or intended for external use. Verify by sending a standard introspection query and checking whether the response contains the full type system
- **IDOR via resolvers**: A resolver accepts an ID argument and returns data without verifying the requesting user's relationship to that resource. Confirmed by authenticating as User A and requesting a resource belonging to User B. If data is returned, the IDOR is confirmed
- **Batching attacks**: The server processes multiple aliased mutations in a single request and no per-operation rate limiting or CAPTCHA is enforced. Confirmed by sending a batched request with 10+ aliased login mutations and observing that all operations execute and return individual results
- **Nested query DoS**: Recursive types exist in the schema (self-referencing or circular references) and no depth or complexity limit rejects deeply nested queries. Confirmed by sending a query with depth 15+ and observing that the server processes it without rejection. Measure response time increase at increasing depths to quantify impact
- **Field-level access gaps**: Querying sensitive fields (passwordHash, apiKey, SSN) on a type returns data that should be restricted. Confirmed by selecting the field in a query as a non-privileged user and receiving a non-null response containing actual sensitive data
- **Alias-based bypass**: Sending 100 aliased calls to an expensive resolver in a single query executes all 100 without throttling or rejection. Confirmed by measuring the response time (should be approximately 100x a single call) and verifying all 100 results are returned
- **Subscription bypass**: Subscribing to another user's events over WebSocket returns real-time data the subscriber should not see. Confirmed by opening a subscription to a resource owned by a different user and triggering an event on that resource
- **GraphQL injection**: Injecting closing quotes and additional operations into an interpolated variable alters the query behavior on the target service. Confirmed by injecting a benign probe (e.g., adding an `__typename` field via injection) and observing it in the response

A finding is theoretical (lower severity) when:
- Introspection is enabled but the schema contains only public types with proper resolver-level auth on every field
- Depth limiting is absent but no recursive types exist in the schema
- Batching is possible but the targeted mutations have independent rate limiting or account lockout at the business logic layer
- Sensitive fields exist on types but are resolved to null by field-level resolver logic regardless of what the type definition exposes

## Common Mitigations and Their Bypasses

**Mitigation: Disable introspection in production**
Bypass: Introspection disabled via `introspection: false` does not prevent schema leakage through other vectors. Check for SDL endpoints (`/graphql/sdl`, `/graphql/schema`), GraphQL Playground or GraphiQL left enabled, error messages that reveal type names ("Cannot query field X on type Y"), and field suggestion features ("Did you mean fieldName?") that allow schema enumeration one field at a time.

**Mitigation: Query depth limiting**
Bypass: Depth limits prevent deeply nested queries but not wide queries. An attacker can request every field on every type at depth 3, which may be within the depth limit but still cause excessive load. Fragment spreads and inline fragments can also be used to restructure queries that stay within depth limits while maximizing resolver invocations. Additionally, some depth limiting libraries only count nesting depth and ignore the total number of fields resolved.

**Mitigation: Query complexity analysis**
Bypass: Complexity scoring depends on accurate cost assignments per field. Default cost values (1 per field) underestimate expensive operations like full-text search, aggregation, or external API calls. If the complexity calculation does not account for list sizes (a field returning 1000 items vs 1), the score will be inaccurate. Attackers can also split expensive queries across multiple requests to stay under per-query limits.

**Mitigation: Resolver-level auth middleware (directives or wrappers)**
Bypass: Auth middleware must be applied to every resolver, including nested resolvers and newly added fields. A single unprotected resolver breaks the security model. Common gaps include: new fields added without the auth directive, nested type resolvers that inherit the parent context but not the auth check, and mutation resolvers where the auth check validates the user but not the specific resource being modified (authentication without authorization).

**Mitigation: Rate limiting at the HTTP request level**
Bypass: As demonstrated above, a single HTTP request can contain hundreds of operations via aliases or batched queries. Effective rate limiting must count operations, not requests. Additionally, WebSocket-based subscriptions and persistent queries may bypass HTTP-level rate limiting entirely.

**Mitigation: Persisted queries (allowlisting known queries)**
Bypass: If the server falls back to accepting arbitrary queries when a persisted query ID is not found (rather than rejecting the request), the protection is ineffective. Some implementations accept both a query ID and a raw query body, with the raw query taking precedence. Check whether the server rejects requests that include a `query` field alongside the persisted query ID.

**Mitigation: Input validation on GraphQL arguments**
Bypass: Custom scalars and input validation only protect against malformed arguments, not against authorization failures or abuse of valid arguments. Validating that an `id` argument is a valid UUID does not prevent an attacker from supplying a valid UUID belonging to another user. Validation that enforces format does not enforce ownership. Additionally, deeply nested input objects may bypass shallow validation that only checks top-level fields.

**Mitigation: Query allowlisting via APQ (Automatic Persisted Queries)**
Bypass: APQ works by hashing queries and caching them. On first request with an unknown hash, most APQ implementations accept the full query body and register it. An attacker can register arbitrary queries by sending them with their SHA-256 hash. True persisted query security requires a build-time extraction step that rejects any query not in the pre-registered set, and the server must reject requests containing a `query` field entirely.

## Rejection Rationalizations

**"GraphQL is just a query language, not a security issue."**
Counter: GraphQL is not merely a query language but a runtime that executes resolvers, connects to databases, and enforces (or fails to enforce) authorization. Every resolver is an attack surface. The flexibility that GraphQL provides to clients — selecting fields, nesting queries, batching operations — is the same flexibility attackers exploit. The query language expands the attack surface compared to REST because the client controls query structure.

**"We disabled introspection so the schema is not exposed."**
Counter: Disabling introspection is one layer of defense, not a complete solution. The schema can still be enumerated through error messages ("Cannot query field X on type Y"), field suggestions in error responses, SDL endpoints, GraphQL IDE tools left enabled, client-side code that contains query fragments, and brute-force field name guessing against common naming patterns. Schema obscurity is not a security boundary.

**"Our API gateway handles authentication so resolvers do not need auth checks."**
Counter: Authentication (verifying identity) at the gateway does not provide authorization (verifying permission) at the resolver level. A gateway that validates JWT tokens ensures the requester is who they claim to be, but it does not ensure they are allowed to access the specific resource they are querying. Every resolver that accesses data must verify the requesting user's permission to access that specific record. Gateway auth prevents unauthenticated access; it does not prevent horizontal privilege escalation between authenticated users.

**"Batching is a feature, not a bug."**
Counter: Batching is indeed a feature for legitimate use cases like reducing HTTP round trips. The security issue is not that batching exists but that it is uncontrolled. Without per-operation rate limiting, batching becomes an amplification vector for brute force, enumeration, and resource exhaustion attacks. The feature itself requires security controls proportional to its power.

**"Depth limiting protects us from DoS."**
Counter: Depth limiting addresses one dimension of query complexity. Wide queries (many fields at shallow depth), aliased queries (same field resolved many times), and queries against list types with large result sets all cause significant server load within typical depth limits. Effective protection requires complexity analysis that accounts for field cost, list multipliers, and alias count in addition to depth.

**"The schema only exposes public data, so introspection is fine."**
Counter: Even if all current types and fields are intended to be public, introspection reveals the internal structure, naming conventions, and relationships of the API. This information accelerates attack planning. Additionally, schemas evolve — a field added next sprint may contain sensitive data, and if introspection remains enabled, it is immediately discoverable. Defense in depth requires disabling introspection regardless of current schema sensitivity.

**"We use GraphQL variables, so injection is not possible."**
Counter: GraphQL variables prevent injection when used correctly within the GraphQL execution engine. However, server-to-server queries constructed via string interpolation in application code do not use the GraphQL variable mechanism. Search for any code that builds GraphQL query strings dynamically. The presence of GraphQL variables in client-facing queries does not guarantee their use in backend service-to-service communication.

## Chaining Opportunities

- **Introspection + IDOR = Mass Data Access**: Introspection reveals the full schema including all queryable types and their ID arguments. The attacker maps every query and mutation, then systematically tests each for missing authorization. A single IDOR on a sensitive type combined with full schema knowledge enables targeted, comprehensive data extraction rather than blind probing.

- **Batching + Weak Auth = Credential Brute Force**: Query batching allows hundreds of login attempts in a single request, bypassing per-request rate limits. If the login mutation returns different errors for invalid username vs invalid password, the attacker can first enumerate valid usernames, then batch brute-force passwords for each confirmed user — all while appearing to send a normal volume of HTTP traffic.

- **Nested Queries + Resource Exhaustion = DoS Enabling Timing Attacks**: A deeply nested query that causes high server load can be calibrated to slow but not crash the server. Under load, the server's response times become inconsistent, creating timing side channels. For example, a query that checks whether a record exists may take 50ms normally but 200ms under load, making boolean-based data extraction viable through timing differences.

- **Subscription + Missing Auth = Real-Time Data Leak**: Unauthorized subscriptions provide a persistent, real-time feed of sensitive events. Unlike a one-time query IDOR, a subscription leak continuously streams data (order updates, messages, notifications, admin events) for as long as the WebSocket connection remains open. The attacker passively collects data without repeated requests that might trigger detection.

- **Field-Level Access Gap + Introspection = Credential Harvesting**: Introspection reveals fields like `apiKey`, `passwordResetToken`, or `internalAuthToken` on user types. If field-level authorization is missing, the attacker queries these fields for every user, extracting credentials that grant direct access to accounts or internal systems without needing to exploit any other vulnerability.

- **GraphQL Injection + Mutation Access = Privilege Escalation**: If a server-to-server GraphQL query is injectable, the attacker can inject mutations (not just queries) into the backend service. For example, injecting a `updateUserRole` mutation into a query that was supposed to only read user data. This turns a read-only injection point into a write-capable exploit, potentially granting admin privileges.

- **Alias-Based Bypass + Enumeration = Data Scraping at Scale**: Combining aliases with an IDOR vulnerability allows an attacker to enumerate and extract data for hundreds of records in a single request. Instead of making 1000 HTTP requests to fetch 1000 user records (which triggers rate limiting), the attacker sends 10 requests with 100 aliased queries each, extracting the same data while staying under HTTP-level rate limits and reducing the chance of detection.

- **Error Message Leakage + Schema Enumeration = Blind Schema Recovery**: When introspection is disabled but error messages reveal type and field names ("Cannot query field 'adminPanel' on type 'Query'"), an attacker can systematically probe field names using common naming conventions. Combined with field suggestion features ("Did you mean 'adminDashboard'?"), the attacker reconstructs significant portions of the schema without introspection access. This recovered schema then enables all other attack patterns that depend on schema knowledge.

- **Persisted Query Bypass + Arbitrary Query Execution = Full Attack Surface**: If persisted query enforcement can be bypassed (by sending a raw query body alongside or instead of a query hash), the attacker gains the ability to send any arbitrary query. This effectively nullifies all server-side query allowlisting and re-enables every other attack vector: deep nesting, alias abuse, introspection, and field enumeration.
