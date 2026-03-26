# DFunc-Bypasser - PHP Disabled Functions Bypass Scanner

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-pentesting-orange.svg)](https://github.com)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](https://github.com)

A powerful PHP security assessment tool that analyzes `disable_functions` and `open_basedir` configurations, identifies available dangerous functions, and detects potential bypass techniques for legitimate penetration testing and security hardening.

---

## 🚀 Quick Start

```bash
# Basic scan with SSL verification
python3 dfunc-bypasser.py --url https://example.com/phpinfo.php

# Skip SSL verification (for self-signed certificates)
python3 dfunc-bypasser.py --url https://192.168.1.100/phpinfo.php --no-verify-ssl

# Scan from local file
python3 dfunc-bypasser.py --file /path/to/saved/phpinfo.html

# Save results to file
python3 dfunc-bypasser.py --url https://example.com/phpinfo.php --output scan_results.txt


Advanced Options

# Custom timeout (default: 10 seconds)
python3 dfunc-bypasser.py --url https://target.com/phpinfo.php --timeout 30

# Custom User-Agent to bypass WAF
python3 dfunc-bypasser.py --url https://target.com/phpinfo.php \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Save results with timestamp
python3 dfunc-bypasser.py --url https://target.com/phpinfo.php \
  --output "scan_$(date +%Y%m%d_%H%M%S).txt"

# Verbose mode for debugging
python3 dfunc-bypasser.py --url https://target.com/phpinfo.php --verbose
