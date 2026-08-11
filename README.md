# Python Security Analyzer

A comprehensive static analysis tool for detecting security vulnerabilities in Python code. Goes beyond simple pattern matching with advanced data flow analysis and framework-specific detection.

## 🎯 Features

### Core Detection
- **SQL Injection**: Detects unsafe SQL queries through string concatenation, f-strings, and .format()
- **Command Injection**: Identifies unsafe command execution with user input (os.system, subprocess, eval, exec)
- **Data Flow Tracking**: Traces tainted data from input sources to dangerous sinks
- **Framework Support**: Specialized analyzers for Flask, Django, FastAPI, and SQLAlchemy
- **Smart Analysis**: Distinguishes between safe parameterized queries and vulnerable patterns

### Supported Patterns
- String concatenation in SQL contexts
- F-string interpolation with user input
- `.format()` and `%` formatting in queries
- SQLAlchemy `text()` and `execute()` misuse
- Tainted data propagation through variables

### Input Sources Tracked
- User input: `input()`, `raw_input()`
- Web frameworks: `request.args`, `request.form`, `request.json`
- File operations: `read()`, `open()`
- Network requests: `requests.get()`, `urllib`

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/handofgod666/python-security-analyzer.git
cd python-security-analyzer
pip install -r requirements.txt
```

### Basic Usage

Scan a single file:
```bash
python -m sqli_detector scan path/to/file.py
```

Scan entire directory:
```bash
python -m sqli_detector scan ./src
```

## 📋 Examples

### Vulnerable Code (Detected)
```python
# SQL Injection - Direct user input in SQL
user_id = input("Enter ID: ")
query = f"SELECT * FROM users WHERE id = {user_id}"  # ❌ Vulnerable

# SQL Injection - Flask request data
username = request.args.get('username')
cursor.execute("SELECT * FROM users WHERE name = '" + username + "'")  # ❌ Vulnerable

# Command Injection - os.system with user input
filename = input("Enter filename: ")
os.system(f"cat {filename}")  # ❌ Vulnerable

# Command Injection - subprocess with shell=True
user_input = input("Command: ")
subprocess.run(f"ls {user_input}", shell=True)  # ❌ Vulnerable
```

### Safe Code (Recommended)
```python
# SQL - Parameterized queries
user_id = input("Enter ID: ")
cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))  # ✅ Safe

# SQL - SQLAlchemy bound parameters
query = text("SELECT * FROM users WHERE id = :id")
session.execute(query, {"id": user_id})  # ✅ Safe

# Commands - subprocess with list arguments
filename = input("Enter filename: ")
subprocess.run(["cat", filename])  # ✅ Safe

# Commands - subprocess with shell=False
user_input = input("Search: ")
subprocess.run(["grep", user_input, "file.txt"], shell=False)  # ✅ Safe
```

## 🔧 CI/CD Integration

### GitHub Actions
The project includes `.github/workflows/security-scan.yml` - add it to your repository to run automated security scans on every push and PR.

### GitLab CI
Use the included `.gitlab-ci.yml` configuration for GitLab pipelines.

### Generic CI/CD
```bash
chmod +x ci_scan.sh
./ci_scan.sh . --fail-on-warning
```

Options:
- First argument: path to scan (default: current directory)
- `--fail-on-warning`: fail the build if vulnerabilities found

## 🧪 Testing

Run the comprehensive test suite:
```bash
python tests/run_tests.py
```

All 31 tests cover:
- Basic SQL injection pattern detection (f-strings, concatenation, .format())
- Data flow analysis (taint tracking)
- SQLAlchemy-specific patterns
- Command injection detection (os.system, subprocess, eval, exec)
- Safe pattern recognition (parameterized queries, subprocess lists)
- CLI functionality

## 📊 How It Works

1. **AST Parsing**: Analyzes Python code structure using Abstract Syntax Trees
2. **Pattern Detection**: Identifies dangerous SQL construction patterns
3. **Data Flow Analysis**: Tracks variables from tainted sources to SQL usage
4. **Framework Detection**: Applies specialized rules for ORMs and web frameworks
5. **Report Generation**: Provides detailed findings with fix recommendations

## 🗺️ Roadmap

### Completed ✅
- [x] SQL injection detection (basic patterns)
- [x] Data flow analysis with taint tracking
- [x] SQLAlchemy support
- [x] CI/CD integration
- [x] Comprehensive test suite
- [x] **Command Injection Detection**: Unsafe `os.system()`, `subprocess`, `eval()`, `exec()` detection

### Planned 🚧
- [ ] **Path Traversal Detection**: Find directory traversal vulnerabilities
- [ ] **XSS Detection**: Identify cross-site scripting risks in templates
- [ ] **SSRF Detection**: Detect Server-Side Request Forgery patterns
- [ ] **Insecure Deserialization**: Find `pickle.loads()` misuse
- [ ] **Hardcoded Secrets**: Scan for API keys, passwords, tokens in code
- [ ] **Cryptographic Issues**: Detect weak encryption algorithms
- [ ] **Configuration Analysis**: Check for debug mode, insecure settings
- [ ] **Dependency Scanning**: Integrate with vulnerability databases
- [ ] **JSON/SARIF Output**: Machine-readable report formats
- [ ] **VS Code Extension**: IDE integration for real-time analysis
- [ ] **Auto-fix Suggestions**: Generate patches for common vulnerabilities

### Future Considerations 💡
- Multi-language support (JavaScript, Go, Java)
- ML-based vulnerability prediction
- Interactive web dashboard
- Custom rule engine for project-specific patterns

## 🤝 Contributing

Contributions are welcome! Areas to help:
- Add new vulnerability detectors
- Improve false positive rate
- Expand framework support
- Write documentation

## 📄 License

MIT License - see LICENSE file for details

## ⚠️ Disclaimer

This tool helps identify potential security issues but does not guarantee complete security. Always perform manual code review and penetration testing for production applications.

## 🔗 Links

- Repository: https://github.com/handofgod666/python-security-analyzer
- Issues: https://github.com/handofgod666/python-security-analyzer/issues
