"""
Web Endpoint Auditor
A multi-threaded reconnaissance tool for discovering hidden paths and administrative interfaces.
"""
import argparse
import concurrent.futures
import logging
import sys
from urllib.parse import urljoin

import requests
import urllib3

# Suppress insecure request warnings for internal/self-signed cert testing
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Configure structured logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger(__name__)

class EndpointAuditor:
    def __init__(self, base_url: str, threads: int = 10, timeout: int = 5):
        # Ensure the base URL is properly formatted
        self.base_url = base_url if base_url.endswith('/') else f"{base_url}/"
        self.threads = threads
        self.timeout = timeout
        
        # Standardize headers to avoid basic WAF blocks that drop blank User-Agents
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) EndpointAuditor/1.0"
        }
        self.discovered_endpoints = []

    def check_path(self, path: str):
        """Executes the HTTP GET request for a specific path."""
        # Strip leading slashes from the wordlist to prevent URL malformation
        clean_path = path.lstrip('/')
        target_url = urljoin(self.base_url, clean_path)

        try:
            # allow_redirects=False lets us see 301/302s instead of blindly following them
            response = requests.get(
                target_url, 
                headers=self.headers, 
                timeout=self.timeout, 
                verify=False, 
                allow_redirects=False
            )

            # Categorize the response
            if response.status_code == 200:
                logger.info(f"[+] 200 OK Found      : {target_url}")
                self.discovered_endpoints.append(target_url)
            elif response.status_code in [301, 302, 307]:
                logger.info(f"[*] {response.status_code} Redirect    : {target_url} -> {response.headers.get('Location')}")
            elif response.status_code in [401, 403]:
                logger.info(f"[!] {response.status_code} Restricted  : {target_url} (Requires Auth)")

        except requests.exceptions.Timeout:
            pass # Fails silently on timeout to keep the multi-threaded output clean
        except requests.exceptions.ConnectionError:
            pass
        except Exception as e:
            logger.debug(f"Error testing {target_url}: {e}")

    def execute_scan(self, wordlist: list):
        """Manages the thread pool for concurrent scanning."""
        logger.info(f"[*] Target: {self.base_url}")
        logger.info(f"[*] Threads: {self.threads}")
        logger.info(f"[*] Payloads: {len(wordlist)}")
        logger.info("-" * 55)

        # Utilize ThreadPoolExecutor for high-performance concurrent HTTP requests
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(self.check_path, wordlist)

        logger.info("-" * 55)
        if not self.discovered_endpoints:
            logger.warning("[-] Scan complete. No fully exposed (200 OK) endpoints discovered.")
        else:
            logger.info(f"[+] Scan complete. {len(self.discovered_endpoints)} exposed endpoints found.")

def main():
    parser = argparse.ArgumentParser(description="Multi-threaded Web Endpoint Auditor")
    parser.add_argument("-u", "--url", required=True, help="Target Base URL (e.g., https://example.com)")
    parser.add_argument("-w", "--wordlist", help="Path to custom wordlist file")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Number of concurrent threads (Default: 10)")
    
    args = parser.parse_args()

    # Fallback default list if no wordlist file is provided
    paths_to_test = [
        "admin", "login", "wp-admin", "dashboard", "api", 
        "backup", "config", "phpmyadmin", ".git/config", "test"
    ]

    if args.wordlist:
        try:
            with open(args.wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                paths_to_test = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.error(f"[!] Wordlist file not found: {args.wordlist}")
            sys.exit(1)

    auditor = EndpointAuditor(base_url=args.url, threads=args.threads)
    
    try:
        auditor.execute_scan(paths_to_test)
    except KeyboardInterrupt:
        logger.warning("\n[!] Scan aborted by user.")
        sys.exit(0)

if __name__ == "__main__":
    main()