# path-checker

`path-checker` is a Python CLI tool for testing **path traversal / directory traversal** issues in web applications.

It sends crafted payloads to a target parameter, tries multiple traversal encodings, and highlights suspicious responses that may indicate unintended file access.

> Use only against systems you own or are explicitly authorized to test.

---

## Features

- Tests common traversal payload styles:
  - direct file paths (`/etc/passwd`, `etc/passwd`)
  - `../`
  - URL-encoded traversal (`%2e%2e%2f`)
  - double URL-encoded traversal (`%252e%252e%252f`)
  - mixed encoding (`..%2f`)
  - `....//` traversal bypass variants
  - simple normalization bypass attempts
- Supports custom endpoint + vulnerable parameter targeting
- Supports known path prefixes (for cases like `/var/www/images/...`)
- Multi-threaded request execution
- Optional proxy support for Burp Suite / debugging
- Optional cookies and custom User-Agent
- Optional SSL verification disable (`--insecure`)
- Basic response metadata collection:
  - status code
  - content length
  - response time
  - small content preview
- Result export to a text file

---

## Requirements

- Python 3.8+
- Packages:
  - `requests`

Install dependencies:

```bash
pip install requests
```

---

## Installation

```bash
git clone https://github.com/Nutzh/path-checker.git
cd path-checker
pip install requests
```

---

## Usage

### Basic example

```bash
python checker.py -u "http://example.com" -p "file"
```

### Test a specific endpoint

```bash
python checker.py -u "http://example.com" -e "download" -p "ticket"
```

### Use Burp as a proxy

```bash
python checker.py -u "http://example.com" -p "file" --proxy "http://127.0.0.1:8080"
```

### Test POST form parameters

```bash
python checker.py -u "http://example.com" -e "download" -p "file" --method post
```

### Test path-segment injection

```bash
python checker.py -u "http://example.com" -e "download" -p "file" --injection-location path
```

### Test a known prefixed path

```bash
python checker.py -u "http://example.com" -e "image" -p "filename" --prefix "/var/www/images/" --files "/etc/passwd"
```

### Add cookies

```bash
python checker.py -u "http://example.com" -p "file" --cookies "session=abc123; auth=xyz789"
```

### Save results

```bash
python checker.py -u "http://example.com" -e "download" -p "file" -o results.txt
```

### Test custom files only

```bash
python checker.py -u "http://example.com" -p "file" --files "/etc/passwd,wp-config.php,.env"
```

---

## Command-line options

| Option | Description | Default |
|---|---|---|
| `-u`, `--url` | Base target URL | required |
| `-e`, `--endpoint` | Endpoint to test | empty |
| `-p`, `--parameter` | Query parameter to inject | required |
| `-d`, `--depth` | Maximum traversal depth | `10` |
| `-t`, `--timeout` | Request timeout in seconds | `5.0` |
| `-o`, `--output` | Save findings to a file | none |
| `-v`, `--verbose` | Verbose logging | off |
| `--threads` | Number of concurrent threads | `10` |
| `--proxy` | Proxy URL | none |
| `--user-agent` | Custom User-Agent | browser-like default |
| `--cookies` | Cookies string (`k=v; k2=v2`) | none |
| `--insecure` | Disable SSL verification | off |
| `--files` | Comma-separated file list | built-in defaults |
| `--ignore-404` | Continue even if target validation returns 404 | off |
| `--method` | HTTP method: `get` or `post` | `get` |
| `--injection-location` | Inject in query parameter or path segment | `query` |
| `--prefix` | Prepend a known base path/prefix to generated payloads | none |

---

## Example workflow

1. Identify a suspicious file/path parameter in the target application.
2. Route traffic through Burp if needed.
3. Run `path-checker` with a focused endpoint and parameter.
4. Review status codes, content length, and preview text.
5. Manually confirm any suspicious hit before reporting it.

Example:

```bash
python checker.py \
  -u "https://target.tld" \
  -e "download" \
  -p "file" \
  --proxy "http://127.0.0.1:8080" \
  --threads 5 \
  --verbose
```

---

## Current limitations

This tool is useful for quick testing, but it is still a lightweight scanner. Current limitations include:

- it is still a heuristic scanner and can produce false positives
- baseline comparison exists, but it is still lightweight rather than deeply content-aware
- POST form support and path injection exist, but JSON / multipart / cookie / header injection are not implemented yet
- signature matching is useful but still limited to a small set of common file patterns
- findings should still be manually confirmed before reporting

---

## Roadmap ideas

Good next improvements would be:

- baseline response comparison
- smarter confidence scoring
- POST / JSON / multipart parameter support
- better deduplication
- export formats like JSON/CSV
- tests and CI
- payload profiles by platform (Linux / Windows / PHP / Java)

---

## Ethical use

This project is intended for:

- authorized security assessments
- lab environments
- self-testing on systems you own

Do **not** use it against targets without permission.

---

## License

No license file is currently present in the repository.
If you want this project to be open-source in a clean way, add a `LICENSE` file (for example MIT).
