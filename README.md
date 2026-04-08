# VulnScan: a Web Endpoint Auditor

A high-performance, multi-threaded reconnaissance utility designed for directory enumeration and administrative interface discovery. 

While tools like `gobuster` or `ffuf` are industry standards, this Python-based auditor was developed to be highly portable, easy to integrate into larger Python automation frameworks, and capable of operating in environments where standard Go or Rust binaries cannot be compiled or imported.

## Features
* **Multi-threaded Execution:** Utilizes Python's `concurrent.futures` to rapidly process large wordlists without blocking I/O, drastically reducing scan times compared to synchronous iterations.
* **Intelligent Response Parsing:** Identifies and logs HTTP 200 (OK), HTTP 30X (Redirects), and HTTP 401/403 (Restricted) status codes to provide a comprehensive map of the application's attack surface.
* **Evasion & Compatibility:** Implements custom User-Agents to avoid rudimentary Web Application Firewall (WAF) blocks and suppresses `urllib3` warnings to seamlessly test internal hosts with self-signed SSL certificates.

## Installation

```bash
git clone [https://github.com/anthony-rizzo-cs/VulnScan.git](https://github.com/anthony-rizzo-cs/VulnScan.git)
cd VulnScan
pip install requests
