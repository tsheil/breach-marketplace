# Tool Setup Reference

Installation methods, version requirements, and troubleshooting for Semgrep and CodeQL.

## Semgrep

### Installation

#### macOS (Homebrew)
```bash
brew install semgrep
```

#### pip (Any platform)
```bash
pip install semgrep
# or
pip3 install semgrep
```

#### pipx (Isolated environment)
```bash
pipx install semgrep
```

#### Docker
```bash
docker run --rm -v "${PWD}:/src" semgrep/semgrep semgrep --config p/security-audit /src
```

### Version Requirements

- Minimum: Semgrep 1.0+
- Recommended: Latest stable release
- Check version: `semgrep --version`

### Verification

```bash
semgrep --version
semgrep --config p/security-audit --test  # Verify rulesets download
```

### Troubleshooting

| Issue | Solution |
|-------|----------|
| `semgrep: command not found` | Ensure install location is on PATH. For pip: check `~/.local/bin` |
| Ruleset download fails | Check internet connectivity. Rulesets are fetched from semgrep.dev |
| Out of memory on large repos | Use `--max-memory <MB>` flag. Exclude large generated/vendor dirs with `--exclude` |
| Slow scan on large repos | Use `--jobs <N>` to control parallelism. Exclude test/vendor directories |
| Python version conflicts | Use `pipx install semgrep` for isolated environment |
| Permission denied | Run `pip install --user semgrep` or use a virtual environment |

### Configuration

Semgrep respects `.semgrepignore` files (same syntax as `.gitignore`) for excluding paths. Create one to skip vendor, test, and generated files:

```
# .semgrepignore
node_modules/
vendor/
*.min.js
*_test.go
test_*.py
__pycache__/
.git/
```

## CodeQL

### Installation

#### GitHub CLI Extension (Recommended)
```bash
gh extension install github/gh-codeql
```

Requires the GitHub CLI (`gh`) to be installed first:
```bash
# macOS
brew install gh

# Linux
sudo apt install gh  # Debian/Ubuntu
sudo dnf install gh  # Fedora
```

#### Direct Binary Download

1. Download the latest CodeQL CLI bundle from [GitHub Releases](https://github.com/github/codeql-cli-binaries/releases)
2. Extract the archive
3. Add the extracted directory to PATH:
   ```bash
   export PATH="$PATH:/path/to/codeql"
   ```
4. Verify: `codeql --version`

#### Homebrew (macOS)
```bash
brew install codeql
```

### Version Requirements

- Minimum: CodeQL CLI 2.15+
- Recommended: Latest stable release
- Check version: `codeql --version`

### Query Packs

CodeQL needs query packs (qlpacks) to run analyses. The CLI bundle includes standard packs. If using a standalone install, download packs:

```bash
codeql pack download codeql/javascript-queries
codeql pack download codeql/python-queries
codeql pack download codeql/java-queries
```

### Verification

```bash
codeql --version
codeql resolve languages    # List supported languages
codeql resolve qlpacks      # List available query packs
```

### Troubleshooting

| Issue | Solution |
|-------|----------|
| `codeql: command not found` | Add CodeQL binary directory to PATH |
| `No QL packs found` | Download packs with `codeql pack download` or use the CLI bundle |
| Database creation fails | Check language detection. Specify `--language` explicitly |
| `No source code found` | Verify `--source-root` points to the correct directory |
| Build fails (compiled languages) | Provide correct build command with `--command`. Ensure build tools are installed |
| Out of memory | Set `--ram=<MB>` flag. Default is 2048 MB. Large projects may need 8192+ |
| Slow database creation | Normal for large codebases. Java/C++ are slower than Python/JS |
| SARIF parse errors | Ensure `--format=sarif-latest` is used. Older formats may have different structure |
| `gh-codeql` extension errors | Update with `gh extension upgrade github/gh-codeql` |

### Database Management

CodeQL databases are large (hundreds of MB to several GB). Management tips:

- **Location**: Store in `.codeql/` or `codeql-db/` in the project root (add to `.gitignore`)
- **Reuse**: Databases can be reused across multiple analyses if the source hasn't changed
- **Cleanup**: Delete database directories when done. They are fully regenerable
- **Upgrade**: After updating CodeQL CLI, upgrade existing databases with `codeql database upgrade <db>`

## Platform-Specific Notes

### macOS

Both tools install cleanly via Homebrew. If using Apple Silicon (M1/M2/M3), ensure you're using native ARM builds:
- Semgrep: Homebrew installs the native version automatically
- CodeQL: The CLI bundle includes universal binaries

### Linux

- Semgrep: pip installation works on all major distributions
- CodeQL: The binary bundle is self-contained and works on any x86_64 Linux

### Windows (WSL)

Both tools work within WSL (Windows Subsystem for Linux). Install as per Linux instructions. Native Windows support:
- Semgrep: Available via pip on Windows
- CodeQL: Windows binaries available in the CLI bundle

## Disk Space Requirements

| Tool | Install Size | Per-Project (DB) |
|------|-------------|-----------------|
| Semgrep | ~100 MB | None (stateless) |
| CodeQL CLI | ~500 MB | 200 MB - 5 GB per database |
| CodeQL Query Packs | ~200 MB per language | N/A |
