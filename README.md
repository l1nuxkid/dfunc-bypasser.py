# dfunc-bypasser.py

# DFunc-Bypasser - PHP Disabled Functions Bypass Scanner

[![Python Version](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Security](https://img.shields.io/badge/security-pentesting-orange.svg)](https://github.com)

A powerful PHP security assessment tool that analyzes `disable_functions` and `open_basedir` configurations, identifies available dangerous functions, and detects potential bypass techniques for legitimate penetration testing and security hardening.

## 📋 Table of Contents

- [Features](#-features)
- [Installation](#-installation)
- [Usage Examples](#-usage-examples)
- [Output Explanation](#-output-explanation)
- [Bypass Methods Detected](#-bypass-methods-detected)
- [Security Recommendations](#-security-recommendations)
- [Configuration Hardening](#-configuration-hardening)
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

## 📦 Installation

### Prerequisites
- Python 3.6 or higher
- pip package manager

### Install Required Dependencies

```bash
# Clone the repository
git clone https://github.com/l1nuxkid/dfunc-bypasser.git
cd dfunc-bypasser

# Install required packages
pip3 install requests urllib3

# Or install from requirements.txt
pip3 install -r requirements.txt
