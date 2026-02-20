# Dangerous Sinks Catalog

A per-language catalog of dangerous functions organized by vulnerability class. This reference covers six languages: **Python**, **JavaScript/TypeScript**, **Java**, **Go**, **Ruby**, and **PHP**. Each entry lists the dangerous function, risk description, and safe alternative with code examples showing vulnerable vs. safe usage.

Use this catalog during code analysis to identify sinks that accept attacker-controlled input and to recommend hardened replacements.

---

## RCE Sinks

Remote Code Execution sinks allow an attacker to execute arbitrary code on the server when user input reaches them without sanitization.

### Python

**Dangerous:** `eval()`, `exec()`, `compile()`, `__import__()`
```python
# VULNERABLE
result = eval(request.args.get("expr"))
```
```python
# SAFE - use ast.literal_eval for data parsing
import ast
result = ast.literal_eval(user_expr)
```

### JavaScript / TypeScript

**Dangerous:** `eval()`, `Function()`, `setTimeout(string)`, `setInterval(string)`, `vm.runInNewContext()`
```javascript
// VULNERABLE
const result = eval(req.query.code);
```
```javascript
// SAFE - avoid eval; use JSON.parse for data
const data = JSON.parse(req.query.data);
```

### Java

**Dangerous:** `Runtime.getRuntime().exec()`, `ProcessBuilder`, `ScriptEngine.eval()`, `javax.el.ExpressionFactory`
```java
// VULNERABLE
Runtime.getRuntime().exec(request.getParameter("cmd"));
```
```java
// SAFE - use an allowlist of permitted commands
if (ALLOWED_ACTIONS.contains(action)) processAction(action);
```

### Go

**Dangerous:** `exec.Command()`, `exec.CommandContext()`, `os.StartProcess()`
```go
// VULNERABLE
exec.Command("sh", "-c", r.URL.Query().Get("cmd")).Run()
```
```go
// SAFE - pass arguments separately, never through a shell
exec.Command("/usr/bin/ls", "-l", safeDir).Run()
```

### Ruby

**Dangerous:** `eval()`, `Kernel.system()`, `Kernel.exec()`, `send()`, `instance_eval()`, `class_eval()`
```ruby
# VULNERABLE
result = eval(params[:expr])
```
```ruby
# SAFE - use an allowlist
ALLOWED = %w[sum average count]
raise "Invalid" unless ALLOWED.include?(params[:op])
```

### PHP

**Dangerous:** `eval()`, `assert()`, `preg_replace()` with `/e`, `create_function()`, `call_user_func()`
```php
// VULNERABLE
eval($_GET['code']);
```
```php
// SAFE - use a dispatch table instead of eval
$allowed = ['sum' => 'doSum', 'avg' => 'doAvg'];
$fn = $allowed[$_GET['action']] ?? null;
if ($fn) $fn($data);
```

---

## SQL Injection Sinks

SQL Injection sinks occur wherever user input is concatenated or interpolated into SQL queries without parameterization.

### Python

**Dangerous:** `cursor.execute()` with string formatting, f-strings in queries, `%` formatting, `.format()`
```python
# VULNERABLE
cursor.execute("SELECT * FROM users WHERE id = " + user_id)
cursor.execute(f"SELECT * FROM users WHERE name = '{name}'")
```
```python
# SAFE - parameterized queries
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

### JavaScript / TypeScript

**Dangerous:** Template literals in SQL, string concatenation with `mysql.query()`, `sequelize.query()` raw interpolation
```javascript
// VULNERABLE
db.query(`SELECT * FROM users WHERE id = ${req.params.id}`);
```
```javascript
// SAFE - parameterized queries
db.query("SELECT * FROM users WHERE id = ?", [req.params.id]);
```

### Java

**Dangerous:** `Statement.execute()` with concatenation, `String.format()` in queries, JPQL concatenation
```java
// VULNERABLE
stmt.executeQuery("SELECT * FROM users WHERE id = '" + userId + "'");
```
```java
// SAFE - PreparedStatement
PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
ps.setString(1, userId);
```

### Go

**Dangerous:** `db.Query()` with `fmt.Sprintf()`, string concatenation in SQL
```go
// VULNERABLE
db.Query(fmt.Sprintf("SELECT * FROM users WHERE id = '%s'", userID))
```
```go
// SAFE - parameterized queries
db.Query("SELECT * FROM users WHERE id = $1", userID)
```

### Ruby

**Dangerous:** `ActiveRecord::Base.connection.execute()` with interpolation, `.where("col = '#{val}'")`
```ruby
# VULNERABLE
User.where("name = '#{params[:name]}'")
```
```ruby
# SAFE - parameterized ActiveRecord
User.where("name = ?", params[:name])
User.where(name: params[:name])
```

### PHP

**Dangerous:** `mysqli_query()` with concatenation, `PDO::query()` with interpolation, `pg_query()`
```php
// VULNERABLE
mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);
```
```php
// SAFE - prepared statements
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $_GET['id']);
$stmt->execute();
```

---

## Command Injection Sinks

Command Injection sinks allow shell metacharacters in user input to break out of intended commands and execute arbitrary OS commands.

### Python

**Dangerous:** `os.system()`, `os.popen()`, `subprocess.call(shell=True)`, `subprocess.Popen(shell=True)`
```python
# VULNERABLE
os.system("cat " + request.args.get("file"))
```
```python
# SAFE - use subprocess with shell=False and argument list
subprocess.run(["cat", filename], shell=False, check=True)
```

### JavaScript / TypeScript

**Dangerous:** `child_process.exec()`, `child_process.execSync()`, `shelljs.exec()`
```javascript
// VULNERABLE
exec("ls " + req.query.dir, callback);
```
```javascript
// SAFE - use execFile with argument array
execFile("ls", [req.query.dir], callback);
```

### Java

**Dangerous:** `Runtime.exec(String)` (single-string form), `ProcessBuilder` with shell invocation
```java
// VULNERABLE
Runtime.getRuntime().exec("ping -c 1 " + input);
```
```java
// SAFE - use ProcessBuilder with explicit argument list
new ProcessBuilder("ping", "-c", "1", host).start();
```

### Go

**Dangerous:** `exec.Command("sh", "-c", userInput)`, `exec.Command("bash", "-c", userInput)`
```go
// VULNERABLE
exec.Command("sh", "-c", "ping -c 1 "+input).Run()
```
```go
// SAFE - pass arguments directly, no shell
exec.Command("ping", "-c", "1", input).Run()
```

### Ruby

**Dangerous:** `system()`, backticks, `%x{}`, `IO.popen()`, `Open3.capture3()` with shell string
```ruby
# VULNERABLE
system("ping -c 1 #{params[:host]}")
```
```ruby
# SAFE - pass arguments as array
system("ping", "-c", "1", host)
```

### PHP

**Dangerous:** `exec()`, `system()`, `passthru()`, `shell_exec()`, `popen()`, backtick operator
```php
// VULNERABLE
system("ping -c 1 " . $_GET['host']);
```
```php
// SAFE - use escapeshellarg
system("ping -c 1 " . escapeshellarg($_GET['host']));
```

---

## SSRF Sinks

Server-Side Request Forgery sinks are HTTP client functions that allow an attacker to control the destination URL, enabling access to internal services, metadata endpoints, or localhost.

### Python

**Dangerous:** `requests.get()`, `requests.post()`, `urllib.request.urlopen()`, `http.client.HTTPConnection()`, `httpx.get()`
```python
# VULNERABLE
resp = requests.get(request.args.get("url"))
```
```python
# SAFE - validate URL against an allowlist
parsed = urlparse(url)
if parsed.hostname not in ALLOWED_HOSTS:
    raise ValueError("Host not allowed")
```

### JavaScript / TypeScript

**Dangerous:** `fetch()`, `axios.get()`, `http.get()`, `https.get()`, `got()`, `node-fetch()`
```javascript
// VULNERABLE
const resp = await fetch(req.query.url);
```
```javascript
// SAFE - validate against allowlist
const parsed = new URL(url);
if (!ALLOWED_HOSTS.includes(parsed.hostname))
    throw new Error("Host not allowed");
```

### Java

**Dangerous:** `HttpURLConnection.openConnection()`, `HttpClient.send()`, `URL.openStream()`, `RestTemplate.getForObject()`
```java
// VULNERABLE
HttpURLConnection conn = (HttpURLConnection) new URL(userUrl).openConnection();
```
```java
// SAFE - validate URL against allowlist
URL parsed = new URL(url);
if (!ALLOWED_HOSTS.contains(parsed.getHost()))
    throw new SecurityException("Host not allowed");
```

### Go

**Dangerous:** `http.Get()`, `http.Post()`, `http.DefaultClient.Do()`, `net.Dial()`
```go
// VULNERABLE
resp, err := http.Get(r.URL.Query().Get("url"))
```
```go
// SAFE - validate URL against allowlist, block internal ranges
parsed, _ := url.Parse(target)
if !isAllowedHost(parsed.Hostname()) {
    http.Error(w, "Host not allowed", 403)
}
```

### Ruby

**Dangerous:** `Net::HTTP.get()`, `open-uri` (`URI.open()`), `HTTParty.get()`, `Faraday.get()`, `RestClient.get()`
```ruby
# VULNERABLE
response = Net::HTTP.get(URI(params[:url]))
```
```ruby
# SAFE - validate host against allowlist
uri = URI.parse(url)
raise "Host not allowed" unless ALLOWED_HOSTS.include?(uri.host)
```

### PHP

**Dangerous:** `file_get_contents()`, `curl_exec()`, `fopen()` with URL, `SoapClient()`, `get_headers()`
```php
// VULNERABLE
$content = file_get_contents($_GET['url']);
```
```php
// SAFE - validate URL against allowlist
$parsed = parse_url($url);
if (!in_array($parsed['host'], $ALLOWED_HOSTS))
    die("Host not allowed");
```

---

## Deserialization Sinks

Deserialization sinks allow attackers to inject malicious objects that execute code during the deserialization process. These are especially dangerous because exploitation often achieves full RCE.

### Python

**Dangerous:** `pickle.loads()`, `pickle.load()`, `yaml.load()` (without `SafeLoader`), `shelve.open()`, `marshal.loads()`, `jsonpickle.decode()`
```python
# VULNERABLE
data = pickle.loads(request.data)
data = yaml.load(raw_yaml)
```
```python
# SAFE - use JSON or yaml.safe_load
data = json.loads(request.data)
data = yaml.safe_load(raw_yaml)
```

### JavaScript / TypeScript

**Dangerous:** `node-serialize` (`unserialize()`), `js-yaml.load()` (default schema), `cryo.parse()`, `funcster`
```javascript
// VULNERABLE
const obj = require("node-serialize").unserialize(req.body.data);
```
```javascript
// SAFE - use JSON.parse which cannot execute code
const obj = JSON.parse(req.body.data);
```

### Java

**Dangerous:** `ObjectInputStream.readObject()`, `XMLDecoder.readObject()`, `XStream.fromXML()`, `Kryo.readObject()`, `SnakeYAML.load()`
```java
// VULNERABLE
ObjectInputStream ois = new ObjectInputStream(inputStream);
Object obj = ois.readObject();
```
```java
// SAFE - use ObjectInputFilter (Java 9+) to restrict allowed classes
ois.setObjectInputFilter(info ->
    ALLOWED_CLASSES.contains(info.serialClass().getName())
        ? ObjectInputFilter.Status.ALLOWED : ObjectInputFilter.Status.REJECTED);
```

### Go

**Dangerous:** `gob.Decode()`, `encoding/xml.Unmarshal()` with custom decoders, `yaml.Unmarshal()` into `interface{}`
```go
// VULNERABLE
dec := gob.NewDecoder(r.Body)
var data interface{}
dec.Decode(&data)
```
```go
// SAFE - decode into a concrete typed struct
var data SafeStruct
json.NewDecoder(r.Body).Decode(&data)
```

### Ruby

**Dangerous:** `Marshal.load()`, `YAML.load()` (Ruby < 3.1), `Oj.load()` with `:object` mode, `Psych.unsafe_load()`
```ruby
# VULNERABLE
obj = Marshal.load(params[:data])
obj = YAML.load(params[:yaml_data])
```
```ruby
# SAFE - use YAML.safe_load or JSON.parse
obj = YAML.safe_load(params[:yaml_data], permitted_classes: [Symbol])
obj = JSON.parse(params[:json_data])
```

### PHP

**Dangerous:** `unserialize()`, `maybe_unserialize()` (WordPress), `igbinary_unserialize()`
```php
// VULNERABLE
$obj = unserialize($_COOKIE['session_data']);
```
```php
// SAFE - use json_decode or restrict allowed classes
$obj = json_decode($_COOKIE['session_data'], true);
$obj = unserialize($data, ['allowed_classes' => ['SafeClass']]);
```

---

## Path Traversal Sinks

Path Traversal sinks allow attackers to read, write, or delete files outside the intended directory by injecting `../` sequences into file paths.

### Python

**Dangerous:** `open()`, `os.path.join()` (does not prevent traversal), `shutil.copy()`, `send_file()`, `pathlib.Path()` without validation
```python
# VULNERABLE
with open("/uploads/" + request.args.get("file")) as f:
    return f.read()
```
```python
# SAFE - resolve and verify path stays within base directory
base = os.path.realpath("/uploads")
filepath = os.path.realpath(os.path.join(base, filename))
if not filepath.startswith(base + os.sep):
    raise ValueError("Path traversal detected")
```

### JavaScript / TypeScript

**Dangerous:** `fs.readFile()`, `fs.readFileSync()`, `fs.createReadStream()`, `path.join()` (does not prevent traversal), `res.sendFile()`
```javascript
// VULNERABLE
res.sendFile("/uploads/" + req.query.file);
```
```javascript
// SAFE - resolve and validate against base directory
const base = path.resolve("/uploads");
const target = path.resolve(base, file);
if (!target.startsWith(base + path.sep))
    return res.status(400).send("Invalid path");
```

### Java

**Dangerous:** `new File()`, `FileInputStream()`, `Files.readAllBytes()`, `Paths.get()`, `ClassLoader.getResource()`
```java
// VULNERABLE
File f = new File("/uploads/" + request.getParameter("file"));
```
```java
// SAFE - canonicalize and validate
File base = new File("/uploads").getCanonicalFile();
File target = new File(base, name).getCanonicalFile();
if (!target.toPath().startsWith(base.toPath()))
    throw new SecurityException("Path traversal detected");
```

### Go

**Dangerous:** `os.Open()`, `os.ReadFile()`, `filepath.Join()` (does not prevent traversal), `http.ServeFile()`
```go
// VULNERABLE
http.ServeFile(w, r, "/uploads/"+r.URL.Query().Get("file"))
```
```go
// SAFE - clean the path and validate prefix
cleaned := filepath.Clean(name)
target := filepath.Join("/uploads", cleaned)
if !strings.HasPrefix(target, "/uploads/") {
    http.Error(w, "Invalid path", 400)
}
```

### Ruby

**Dangerous:** `File.read()`, `File.open()`, `IO.read()`, `send_file()`, `Pathname.new()`
```ruby
# VULNERABLE
send_file("/uploads/#{params[:file]}")
```
```ruby
# SAFE - expand path and verify it stays within base
base = File.realpath("/uploads")
target = File.realpath(File.join(base, filename))
raise "Path traversal" unless target.start_with?(base + "/")
```

### PHP

**Dangerous:** `file_get_contents()`, `fopen()`, `include()`, `require()`, `readfile()`, `file()`
```php
// VULNERABLE
readfile("/uploads/" . $_GET['file']);
```
```php
// SAFE - resolve realpath and validate
$base = realpath("/uploads");
$target = realpath("/uploads/" . $file);
if ($target === false || strpos($target, $base . DIRECTORY_SEPARATOR) !== 0)
    die("Invalid path");
```

---

## Template Injection Sinks

Server-Side Template Injection (SSTI) sinks allow attackers to inject template directives that are evaluated on the server, potentially achieving RCE.

### Python

**Dangerous:** `jinja2.Template()` with user input, `jinja2.Environment().from_string()`, `mako.template.Template()`, `django.template.Template()`
```python
# VULNERABLE
template = Template(request.args.get("tmpl"))
return template.render()
```
```python
# SAFE - render user input as data, not as template source
env = Environment(loader=BaseLoader(), autoescape=True)
tmpl = env.from_string("Hello {{ name }}")
return tmpl.render(name=request.args.get("name"))
```

### JavaScript / TypeScript

**Dangerous:** `Handlebars.compile()` with user input, `ejs.render(userString)`, `pug.render(userString)`, `nunjucks.renderString()`
```javascript
// VULNERABLE
const output = ejs.render(req.body.template, data);
```
```javascript
// SAFE - use static templates, pass user input as data only
const output = ejs.renderFile("views/page.ejs", { name: req.body.name });
```

### Java

**Dangerous:** `Freemarker Template()` with user string, `Velocity.evaluate()`, `Thymeleaf SpringTemplateEngine` with user content
```java
// VULNERABLE
Template t = new Template("dynamic", new StringReader(userInput), cfg);
t.process(dataModel, out);
```
```java
// SAFE - load templates from a fixed directory
cfg.setDirectoryForTemplateLoading(new File("/templates"));
Template t = cfg.getTemplate("page.ftl");
t.process(Map.of("name", userInput), out);
```

### Go

**Dangerous:** `template.New().Parse()` with user input, `html/template` and `text/template` with user-controlled strings
```go
// VULNERABLE
t, _ := template.New("page").Parse(r.URL.Query().Get("tmpl"))
t.Execute(w, data)
```
```go
// SAFE - parse templates from files, pass user input as data
t, _ := template.ParseFiles("templates/page.html")
t.Execute(w, map[string]string{"Name": userInput})
```

### Ruby

**Dangerous:** `ERB.new()` with user input, `Slim::Template.new()`, `Haml::Engine.new()`, `Liquid::Template.parse()`
```ruby
# VULNERABLE
template = ERB.new(params[:template])
output = template.result(binding)
```
```ruby
# SAFE - use static templates, pass user input via locals
template = ERB.new(File.read("views/page.erb"))
output = template.result_with_hash(name: params[:name])
```

### PHP

**Dangerous:** `Twig` `createTemplate()` with user input, `Blade::compileString()`, `Smarty::fetch("string:$input")`
```php
// VULNERABLE
$template = $twig->createTemplate($_GET['tmpl']);
echo $template->render([]);
```
```php
// SAFE - load templates from filesystem, pass user input as context
$twig = new \Twig\Environment(new FilesystemLoader('/templates'), ['autoescape' => 'html']);
echo $twig->render('page.html.twig', ['name' => $_GET['name']]);
```

---

## XSS Sinks (Server-Side)

Server-Side XSS sinks are locations in server-rendered output where user input is written to HTML without proper escaping, enabling script injection in the browser.

### Python

**Dangerous:** `Markup()` / `mark_safe()` with user input, `|safe` filter in Jinja2/Django, `render_template_string()` without escaping
```python
# VULNERABLE - mark_safe (Django) or |safe filter (Jinja2)
return HttpResponse(mark_safe(f"<div>{user_input}</div>"))
return render_template_string("<div>{{ data|safe }}</div>", data=user_input)
```
```python
# SAFE - let the template engine auto-escape; never use |safe on user data
return render(request, "page.html", {"content": user_input})
```

### JavaScript / TypeScript

**Dangerous:** `dangerouslySetInnerHTML` (React), `element.innerHTML =`, `document.write()`, `res.send()` with raw HTML, `$.html()`
```javascript
// VULNERABLE - raw interpolation in HTML; dangerouslySetInnerHTML
res.send(`<h1>Hello ${req.query.name}</h1>`);
<div dangerouslySetInnerHTML={{ __html: userInput }} />
```
```javascript
// SAFE - escape output or render as text content
res.send(`<h1>Hello ${escapeHtml(req.query.name)}</h1>`);
<div>{userInput}</div>
```

### Java

**Dangerous:** `PrintWriter.write()` with raw HTML, `response.getWriter().print()`, JSP `<%= %>` without encoding, `th:utext` in Thymeleaf
```java
// VULNERABLE
response.getWriter().print("<div>" + userInput + "</div>");
```
```java
// SAFE - use OWASP encoder
response.getWriter().print("<div>" + Encode.forHtml(userInput) + "</div>");
```
```html
<!-- VULNERABLE: th:utext (unescaped) vs SAFE: th:text (escaped) -->
<div th:utext="${userInput}"></div> <!-- VULNERABLE -->
<div th:text="${userInput}"></div>  <!-- SAFE -->
```

### Go

**Dangerous:** `fmt.Fprintf(w, ...)` with user input, `io.WriteString(w, ...)`, `text/template` (no auto-escaping), `template.HTML()` cast
```go
// VULNERABLE - raw Fprintf or template.HTML() bypasses escaping
fmt.Fprintf(w, "<div>%s</div>", userInput)
tmpl.Execute(w, map[string]interface{}{"Input": template.HTML(userInput)})
```
```go
// SAFE - use html/template and pass plain strings (auto-escaped)
tmpl := template.Must(template.New("p").Parse("<div>{{.Input}}</div>"))
tmpl.Execute(w, map[string]string{"Input": userInput})
```

### Ruby

**Dangerous:** `raw()`, `html_safe`, `.html_safe` on user input, `<%== expression %>` in ERB
```ruby
# VULNERABLE
<%= raw(params[:name]) %>
<%= params[:name].html_safe %>
```
```ruby
# SAFE - default ERB output auto-escapes
<%= params[:name] %>
```

### PHP

**Dangerous:** `echo`/`print` with raw user input, `<?= $var ?>` without escaping, `{!! $var !!}` in Blade, `|raw` in Twig
```php
// VULNERABLE
echo "<div>" . $_GET['name'] . "</div>";
{!! $userInput !!}
```
```php
// SAFE - use htmlspecialchars; use {{ }} in Blade (auto-escaped)
echo "<div>" . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8') . "</div>";
{{ $userInput }}
```

---

## Usage Notes

- **Context matters.** A function is only a dangerous sink when it processes attacker-controlled input. Trace data flow from sources (HTTP parameters, headers, cookies, file uploads) to these sinks.
- **Defense in depth.** Even when using safe alternatives, apply input validation (allowlists, type checks, length limits) as an additional layer.
- **Framework defaults.** Vulnerabilities often arise when developers bypass safe defaults using raw/unsafe modes (`|safe`, `html_safe`, `{!! !!}`, `th:utext`, `text/template`, `shell=True`).
