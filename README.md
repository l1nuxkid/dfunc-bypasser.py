# DFunc-Bypasser - PHP Disabled Functions Bypass Scanner

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-pentesting-orange.svg)](https://github.com)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey.svg)](https://github.com)

A powerful PHP security assessment tool that analyzes `disable_functions` and `open_basedir` configurations, identifies available dangerous functions, and detects potential bypass techniques for legitimate penetration testing and security hardening.

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Usage Examples](#-usage-examples)
- [Output Explanation](#-output-explanation)
- [Bypass Methods Detected](#-bypass-methods-detected)
- [Security Recommendations](#-security-recommendations)
- [Configuration Hardening](#-configuration-hardening)
- [Troubleshooting](#-troubleshooting)
- [Disclaimer](#-disclaimer)
- [License](#-license)

## 🚀 Features

- **PHP Configuration Analysis**: Extracts disabled functions from phpinfo()
- **Module Detection**: Identifies installed PHP modules (mbstring, imap, imagick, etc.)
- **Dangerous Function Scanner**: Lists all available high-risk functions
- **Bypass Method Detection**: Identifies potential bypass techniques including:
  - LD_PRELOAD via mail() and putenv()
  - IMAP RCE vectors
  - PHP-FPM/FastCGI exploitation paths
  - PCNTL process forking attacks
  - ImageMagick vulnerability detection
- **SSL/TLS Support**: Handles HTTPS with certificate verification options
- **Security Recommendations**: Provides actionable hardening advice
- **Multiple Input Sources**: Supports both URLs and local phpinfo files
- **Color-Coded Output**: Easy-to-read terminal output
- **Report Generation**: Save results to file for documentation
- **Verbose Mode**: Detailed debugging information
- **Custom User-Agent**: Bypass WAF restrictions

## 📦 Installation

### Prerequisites
- Python 3.6 or higher
- pip package manager
- Git (for cloning repository)

### Step-by-Step Installation

```bash
# 1. Clone the repository
git clone https://github.com/l1nuxkid/dfunc-bypasser.git
cd dfunc-bypasser

# 2. Install required packages
pip3 install requests urllib3

# 3. Verify installation
python3 dfunc-bypasser.py --help

# Optional: Create requirements.txt and install from it
cat > requirements.txt << EOF
requests>=2.28.0
urllib3>=1.26.0
EOF

pip3 install -r requirements.txt

# Optional: Make script executable
chmod +x dfunc-bypasser.py



🚀 Quick Start

# Basic scan with SSL verification
python3 dfunc-bypasser.py --url https://example.com/phpinfo.php

# Skip SSL verification (for self-signed certificates)
python3 dfunc-bypasser.py --url https://192.168.1.100/phpinfo.php --no-verify-ssl

# Scan from local file
python3 dfunc-bypasser.py --file /path/to/saved/phpinfo.html

# Save results to file
python3 dfunc-bypasser.py --url https://example.com/phpinfo.php --output scan_results.txt


Advanced Usage

# Custom User-Agent to bypass WAF
python3 dfunc-bypasser.py --url https://example.com/phpinfo.php \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"

# Save results with timestamp
python3 dfunc-bypasser.py --url https://example.com/phpinfo.php \
  --output "scan_$(date +%Y%m%d_%H%M%S).txt"

# Complete scan with all options
python3 dfunc-bypasser.py \
  --url https://example.com/phpinfo.php \
  --no-verify-ssl \
  --timeout 20 \
  --user-agent "Security Scanner v1.0" \
  --output results.txt \
  --verbose






