# Framework Security Patterns Reference

Quick-reference security patterns for common frameworks. For each framework: critical settings, injection vectors, auth patterns, and common security misses. This is a checklist, not a tutorial.

---

## Django

**Critical Settings**
- `SECRET_KEY`: Must not be hardcoded in `settings.py` or committed to version control. Check for default/weak values and rotation policy.
- `DEBUG = True`: Fatal in production. Exposes stack traces, SQL queries, settings, and installed apps via debug error pages.
- `ALLOWED_HOSTS`: Empty list with `DEBUG=False` rejects all requests, but a wildcard `['*']` permits host header injection.
- `SECURE_SSL_REDIRECT`, `SECURE_HSTS_SECONDS`, `SECURE_HSTS_INCLUDE_SUBDOMAINS`: Should be enabled in production.
- `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, `CSRF_COOKIE_SECURE`: Must be `True` for HTTPS deployments.
- `X_FRAME_OPTIONS`: Default `DENY` — check if weakened or removed.

**Injection Vectors**
- `raw()`, `extra()`, `RawSQL()`: ORM escape hatches that accept raw SQL. Grep for these aggressively.
- `cursor.execute()` with string formatting instead of parameterized queries.
- Template `|safe` filter and `mark_safe()`: Bypass autoescape. Every usage is a potential XSS sink.
- `{% autoescape off %}` blocks in templates.
- `json.loads()` on user input fed into ORM `__` lookups — can manipulate query operators.

**Auth Patterns**
- `@login_required` decorator: Check for views missing it, especially class-based views where method-level decorators are easy to forget.
- `LoginRequiredMixin` for class-based views — must be the first mixin in MRO.
- `@permission_required` and `@user_passes_test`: Verify the test function is correct.
- Django admin: Check `admin.site.urls` exposure, admin model permissions, and custom admin actions.
- `is_staff` vs `is_superuser` confusion in custom permission checks.

**Common Security Misses**
- Admin panel on default `/admin/` path without IP restriction or 2FA.
- `CSRF_TRUSTED_ORIGINS` overly broad or including attacker-controllable domains.
- `ModelForm` without explicit `fields` (pre-Django 1.8 pattern, still seen in legacy code).
- File upload handling via `FileField`/`ImageField` without content-type validation beyond extension.
- `pickle`-based session backend (`django.contrib.sessions.backends.cache` with Memcached can deserialize attacker-controlled data if cache is shared/exposed).
- Missing `CONN_MAX_AGE` considerations for connection pooling credential rotation.

---

## Express.js

**Critical Settings**
- `helmet` middleware: Missing entirely is the most common issue. Check for `helmet()` in the middleware chain.
- `trust proxy`: Misconfigured value allows IP spoofing via `X-Forwarded-For`. Must match the actual proxy topology.
- `body-parser` / `express.json()` limits: Default is 100kb. No limit or high limit enables request flooding.
- `express.static()` root path: Relative paths can enable path traversal. Must use `path.join(__dirname, ...)` or absolute path.
- `app.disable('x-powered-by')` or use `helmet` — leaking `Express` in response headers aids fingerprinting.

**Injection Vectors**
- Template injection in EJS: `<%-` (unescaped output) vs `<%=` (escaped). Grep for `<%-` with user-controlled data.
- Pug template injection via unquoted attribute interpolation.
- `eval()`, `Function()`, `vm.runInNewContext()` with user input.
- `child_process.exec()` with string interpolation — use `execFile` with argument arrays instead.
- RegExp DoS: User-controlled regex patterns or routes with backtracking-vulnerable patterns.
- Prototype pollution via `qs` (query string parser) or `body-parser` — `__proto__`, `constructor.prototype` payloads.

**Auth Patterns**
- No built-in auth — check for Passport.js, express-session, JWT libraries (jsonwebtoken, jose).
- Session configuration: `secret` strength, `resave: false`, `saveUninitialized: false`, `cookie.secure`, `cookie.httpOnly`, `cookie.sameSite`.
- JWT: Check for `algorithms` whitelist in `verify()` — missing this enables `alg: none` attacks.
- Middleware ordering: Auth middleware must be applied before route handlers. Check for routes defined before `app.use(authMiddleware)`.

**Common Security Misses**
- No CSRF protection by default — requires `csurf` or equivalent.
- Error handler exposing stack traces: `app.use((err, req, res, next) => res.status(500).json({ error: err.stack }))`.
- `cors()` with `origin: true` or `origin: '*'` with `credentials: true`.
- Missing rate limiting on auth endpoints.
- `req.params`, `req.query`, `req.body` used without type checking — everything is a string (or object via prototype pollution).
- File uploads via `multer` without file type validation, size limits, or filename sanitization.
- `res.redirect(req.query.url)` — open redirect.

---

## Spring Boot

**Critical Settings**
- Actuator endpoints: `/actuator/env`, `/actuator/heapdump`, `/actuator/beans`, `/actuator/mappings` — must be secured or disabled in production. Check `management.endpoints.web.exposure.include`.
- `server.error.include-stacktrace`: Must be `never` in production.
- `spring.jackson.deserialization.FAIL_ON_UNKNOWN_PROPERTIES`: `false` enables mass assignment.
- `spring.datasource.*`: Credentials in `application.properties` or `application.yml` committed to VCS.
- `server.servlet.session.cookie.secure`, `server.servlet.session.cookie.http-only`: Must be `true`.

**Injection Vectors**
- SpEL injection: `@Value("#{...}")`, `@PreAuthorize("...")`, `@Cacheable(key="...")` with user-controlled expressions.
- Thymeleaf SSTI: `__${...}__` preprocessing expressions. Occurs when template names or fragments are user-controlled.
- JDBC template with string concatenation instead of `?` placeholders.
- JPA `@Query` with `:#{#param}` SpEL inside JPQL — can inject into query structure.
- Jackson polymorphic deserialization: `@JsonTypeInfo(use = Id.CLASS)` or `enableDefaultTyping()` — enables RCE via gadget chains.
- XML external entity (XXE) via `RestTemplate` or JAXB unmarshalling without disabling external entities.

**Auth Patterns**
- Spring Security filter chain: Check `WebSecurityConfigurerAdapter` (deprecated) or `SecurityFilterChain` bean configuration.
- `@PreAuthorize` vs `@Secured` vs `@RolesAllowed`: Mixing styles causes confusion. `@PreAuthorize` supports SpEL, others do not.
- `antMatchers`/`requestMatchers` ordering: First match wins. Overly broad patterns early in the chain can bypass later restrictions.
- `.permitAll()` on endpoints that should be authenticated.
- Method-level security: `@EnableGlobalMethodSecurity` or `@EnableMethodSecurity` must be present for `@PreAuthorize` to work.

**Common Security Misses**
- `@ModelAttribute` mass assignment: All request parameters bound to object fields unless explicitly restricted.
- CORS via `@CrossOrigin` annotation with default `allowedOrigins = "*"`.
- Missing CSRF for state-changing operations when sessions are used (disabled by default for stateless/JWT APIs).
- Actuator on the same port as the application without separate security configuration.
- `spring-boot-devtools` on the classpath in production.
- H2 console enabled and exposed (`spring.h2.console.enabled=true`).
- Path traversal in `ResourceHttpRequestHandler` or custom file-serving controllers.

---

## Rails

**Critical Settings**
- `secret_key_base`: Exposed in `config/secrets.yml`, `config/credentials.yml.enc`, or environment. Enables cookie forgery and RCE via deserialization.
- `config.force_ssl`: Must be `true` in production.
- `config.action_dispatch.cookies_serializer`: `:marshal` enables RCE if `secret_key_base` is compromised. Prefer `:json`.
- `config.consider_all_requests_local`: Must be `false` in production — controls debug info exposure.
- `config.filter_parameters`: Must include `:password`, `:token`, `:secret`, etc. for log filtering.

**Injection Vectors**
- Mass assignment: `params.permit` (strong parameters) bypass via nested attributes, array parameters, or `permit!`.
- `render inline:` with user-controlled ERB templates.
- `YAML.load` (pre-Psych 4.0): Unsafe deserialization. Must use `YAML.safe_load`.
- `Marshal.load` on user-controlled data: Direct RCE.
- Raw SQL: `where("name = '#{params[:name]}'")`, `order(params[:sort])`, `pluck(params[:col])`, `select(params[:fields])`.
- `html_safe`, `raw()`, `<%== %>` in views: Bypass output escaping.
- `send(params[:method])` or `public_send` with user-controlled method names.

**Auth Patterns**
- Devise: Check `confirmable`, `lockable`, `timeoutable` modules enabled. Check `password_length` range.
- `before_action :authenticate_user!` — verify it is not skipped with `skip_before_action` on sensitive controllers.
- Authorization gems (Pundit, CanCanCan): Check for `authorize` calls in every controller action. Look for `skip_authorization`.
- API auth: Check token-based auth implementation for timing attacks in comparison.

**Common Security Misses**
- `protect_from_forgery` with `:null_session` in API controllers — verify API auth compensates.
- ActiveStorage direct upload without content type or size validation.
- `redirect_to params[:url]` — open redirect.
- Regex anchors: Ruby `\A` and `\z` vs `^` and `$` — the latter match line boundaries, enabling bypass with newlines.
- `Rack::Utils.parse_nested_query` parameter pollution and type confusion.
- Development secrets committed in `config/secrets.yml` or `config/master.key`.

---

## Laravel

**Critical Settings**
- `.env` file: Must not be web-accessible. Check `.htaccess`/nginx config for blocking dotfiles. Check `.gitignore`.
- `APP_DEBUG=true`: Exposes Ignition error page with environment variables, database credentials, and code execution (CVE-2021-3129).
- `APP_KEY`: Must be set and not committed. Used for encryption, cookie signing.
- `config/cors.php`: Check `allowed_origins`, `supports_credentials` combination.
- `config/session.php`: Check `secure`, `http_only`, `same_site` values.

**Injection Vectors**
- Mass assignment: `$fillable` whitelist vs `$guarded` blacklist. Empty `$guarded = []` permits all fields.
- Blade `{!! $var !!}`: Unescaped output. Grep aggressively. Also `@php echo`, `<?= ?>`.
- Raw queries: `DB::raw()`, `whereRaw()`, `selectRaw()`, `orderByRaw()`, `havingRaw()` with string interpolation.
- `request()->input()` returns mixed types — string, array, or null — leading to type juggling.
- File upload: Check `mimes` vs `mimetypes` validation rules. Extension-based validation is spoofable.
- `unserialize()` on user input: Direct RCE via POP chains.

**Auth Patterns**
- Middleware groups: `auth`, `auth:sanctum`, `auth:api`. Check route groups for missing middleware.
- Gates and Policies: Check for `$this->authorize()` calls in controllers. Look for missing authorization.
- `Route::model()` binding: Assumes the authenticated user owns the resource unless scoped. Check for IDOR.
- Sanctum/Passport token scopes: Verify scope enforcement on sensitive endpoints.

**Common Security Misses**
- Route model binding without ownership scoping — `User::find($id)` returns any user's data.
- `storage/` or `bootstrap/cache/` web-accessible.
- Debug bar (`barryvdh/laravel-debugbar`) enabled in production — leaks queries, session data, request data.
- Queue job deserialization: Untrusted data in queue payloads can trigger POP chain exploitation.
- Missing `throttle` middleware on login/registration endpoints.
- `config:cache` in production without `env()` calls outside config files.
- Telescope installed and accessible without auth in production.

---

## Next.js

**Critical Settings**
- `NEXT_PUBLIC_*` environment variables: Exposed to the browser. Grep for secrets with this prefix.
- `next.config.js`: Check `poweredByHeader: false`, `reactStrictMode: true`.
- `headers()` in `next.config.js`: Check for security headers (CSP, HSTS, X-Frame-Options).
- Image optimization: `remotePatterns`/`domains` in `next.config.js` — overly permissive allows SSRF via image optimization proxy.

**Injection Vectors**
- API routes (`pages/api/` or `app/api/`): No auth by default. Each route is an independent serverless function.
- `getServerSideProps` / Server Components: Data returned is serialized to the client. Sensitive server-side data leaks if included in props.
- SSRF via server-side `fetch()` in `getServerSideProps`, Server Components, or API routes with user-controlled URLs.
- `dangerouslySetInnerHTML`: XSS sink. Grep for it with user-controlled values.
- Redirect injection: `redirect()` or `NextResponse.redirect()` with user-controlled destination.
- `eval()` or dynamic `import()` with user-controlled paths in API routes.

**Auth Patterns**
- NextAuth.js / Auth.js: Check `callbacks.session`, `callbacks.jwt` for data exposure. Verify `NEXTAUTH_SECRET` is set and strong.
- Middleware-based auth (`middleware.ts`): Check `matcher` config — must cover all protected routes. Middleware does not run on API routes in some configurations.
- Server Component auth: Each server component must independently verify auth — no automatic propagation.

**Common Security Misses**
- API routes without any auth check — especially CRUD operations.
- `revalidatePath`/`revalidateTag` triggered by unauthenticated requests — cache poisoning.
- ISR (Incremental Static Regeneration) serving stale content with outdated auth state.
- Server Actions (`'use server'`) callable from the client — each must validate auth and input independently.
- `next.config.js` rewrites/redirects with user-controlled path segments.
- Exposed source maps in production (`productionBrowserSourceMaps: true`).
- Missing CSRF on Server Actions (automatic in Next.js 14+ but verify).

---

## Flask

**Critical Settings**
- `FLASK_DEBUG=1` / `app.run(debug=True)`: Enables Werkzeug debugger with code execution. Check for PIN protection bypass.
- `SECRET_KEY`: Must be strong and not hardcoded. Weak keys enable session cookie forgery.
- `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY`, `SESSION_COOKIE_SAMESITE`: Must be set for production.
- `MAX_CONTENT_LENGTH`: Must be set to prevent request flooding via large uploads.
- `PREFERRED_URL_SCHEME`: Should be `https` in production for correct URL generation.

**Injection Vectors**
- Jinja2 SSTI: `render_template_string(user_input)` or `Template(user_input).render()`. Also `|safe` filter and `Markup()` wrapper bypass autoescape.
- SQL injection via string formatting: `db.engine.execute("SELECT * FROM users WHERE id = %s" % user_id)`.
- `send_file()` and `send_from_directory()` with user-controlled paths — path traversal if not properly rooted.
- `subprocess.call(user_input, shell=True)` — common in Flask apps that wrap CLI tools.
- `pickle.loads()` on user-controlled data — Flask's default `SecureCookieSessionInterface` is signed but uses pickle. Custom session stores may deserialize unsafely.
- `eval()`, `exec()` with user input in calculator/sandbox-style apps.

**Auth Patterns**
- No built-in auth — check for Flask-Login, Flask-Security, Flask-JWT-Extended.
- `@login_required` decorator from Flask-Login. Check for routes missing it.
- `before_request` hooks for global auth — verify they cover all blueprints.
- Flask-CORS: Check `supports_credentials` with `origins='*'`.

**Common Security Misses**
- No CSRF protection by default — requires Flask-WTF or manual implementation.
- `app.secret_key = 'dev'` or similar weak development key left in production.
- Blueprint registration without auth middleware — new blueprints added without security review.
- `jsonify()` on SQLAlchemy model objects can serialize unintended fields.
- File uploads without content-type validation, size limits, or filename sanitization (`werkzeug.utils.secure_filename` not called).
- Missing rate limiting entirely — requires Flask-Limiter or equivalent.
- Error handlers returning raw exception messages in production.

---

## FastAPI

**Critical Settings**
- CORS middleware: `allow_origins=["*"]` with `allow_credentials=True` is an exploitable misconfiguration.
- `docs_url` and `redoc_url`: Swagger UI exposed in production by default. Set to `None` in production.
- `debug=True` in `FastAPI()` constructor: Exposes stack traces.
- Uvicorn `--reload` and `--host 0.0.0.0` in production — check deployment scripts.

**Injection Vectors**
- SQLAlchemy raw queries: `session.execute(text(f"SELECT * FROM users WHERE id = {user_id}"))`.
- Pydantic validation bypass: `model_config = ConfigDict(extra="allow")` or `class Config: extra = "allow"` accepts arbitrary fields. Also `json()` on models may expose unintended fields.
- File upload handling: `UploadFile` without size limits, content-type validation, or filename sanitization.
- `BackgroundTasks` with user-controlled function references or arguments.
- `eval()` or `exec()` in endpoints that process expressions or formulas.
- Response model data leak: Missing `response_model_exclude` can return sensitive fields (passwords, internal IDs).

**Auth Patterns**
- Dependency injection auth: `Depends(get_current_user)`. Check for endpoints missing this dependency.
- OAuth2 password bearer / HTTP bearer: Check token validation implementation for `alg: none`, missing expiry, and key confusion.
- `Security` dependencies vs `Depends`: `Security` integrates with OpenAPI docs but behavior is the same.
- Scope-based auth: Verify scopes are checked on sensitive endpoints, not just that a token exists.

**Common Security Misses**
- No built-in CSRF protection. Stateless JWT APIs are immune but session-based FastAPI apps are not.
- Missing rate limiting — requires `slowapi` or custom middleware.
- Pydantic `orm_mode` / `from_attributes` exposing all ORM model fields in responses.
- Background tasks running with the same privilege context as the request handler — no privilege separation.
- Missing input size limits on request body (relies on reverse proxy or ASGI server config).
- WebSocket endpoints without authentication — `Depends()` not automatically applied to WebSocket routes.
- Path parameters used directly in file operations or database queries without validation beyond Pydantic type coercion.
- `pickle`-based caching (Redis with pickle serializer) with shared cache accessible to other services.
