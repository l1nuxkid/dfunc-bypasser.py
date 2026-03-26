#!/usr/bin/env python3
"""
PHP Security Scanner - Check disabled functions and potential bypass vectors
Enhanced with SSL support and additional features
"""

import argparse
import requests
import ssl
import urllib3
import sys
from urllib.parse import urlparse
import re

# Disable SSL warnings (use with caution - for testing only)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Colors:
    """ANSI color codes for terminal output"""
    reset = '\033[0m'
    red = '\033[31m'
    green = '\033[32m'
    orange = '\033[33m'
    blue = '\033[34m'
    yellow = '\033[93m'
    cyan = '\033[96m'
    bold = '\033[1m'

class PHPInfoScanner:
    def __init__(self, verify_ssl=False, timeout=10, user_agent=None):
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.session = requests.Session()
        
        # Configure session
        self.session.verify = verify_ssl
        self.session.headers.update({
            'User-Agent': self.user_agent
        })
        
        # Suppress SSL warnings if not verifying
        if not verify_ssl:
            import warnings
            warnings.filterwarnings('ignore', message='Unverified HTTPS request')
    
    def fetch_phpinfo(self, source):
        """Fetch PHP info from URL or file"""
        try:
            if source.startswith('http://') or source.startswith('https://'):
                print(f"{Colors.blue}[*] Fetching PHP info from: {source}{Colors.reset}")
                response = self.session.get(source, timeout=self.timeout)
                response.raise_for_status()
                return response.text
            else:
                print(f"{Colors.blue}[*] Reading PHP info from file: {source}{Colors.reset}")
                with open(source, 'r', encoding='utf-8', errors='ignore') as f:
                    return f.read()
        except requests.exceptions.SSLError as e:
            print(f"{Colors.red}[-] SSL Error: {e}{Colors.reset}")
            print(f"{Colors.yellow}[!] Try using --no-verify-ssl or --insecure flag{Colors.reset}")
            sys.exit(1)
        except requests.exceptions.RequestException as e:
            print(f"{Colors.red}[-] Request failed: {e}{Colors.reset}")
            sys.exit(1)
        except FileNotFoundError as e:
            print(f"{Colors.red}[-] File not found: {e}{Colors.reset}")
            sys.exit(1)
        except Exception as e:
            print(f"{Colors.red}[-] Error: {e}{Colors.reset}")
            sys.exit(1)
    
    def extract_disabled_functions(self, phpinfo_content):
        """Extract disabled functions from PHP info content"""
        try:
            # Pattern for disable_functions in PHP info
            patterns = [
                r'disable_functions</td><td class="v">([^<]+)</td>',
                r'disable_functions\s*=>\s*([^\n]+)',
                r'disable_functions["\']?\s*=>\s*["\']?([^"\']+)["\']?'
            ]
            
            for pattern in patterns:
                match = re.search(pattern, phpinfo_content)
                if match:
                    functions = match.group(1).strip()
                    if functions:
                        return [f.strip() for f in functions.split(',') if f.strip()]
            
            # Fallback: try to find in table format
            table_match = re.search(r'<td class="e">disable_functions</td><td class="v">(.*?)</td>', phpinfo_content, re.DOTALL)
            if table_match:
                functions = table_match.group(1).strip()
                return [f.strip() for f in functions.split(',') if f.strip()]
            
            return []
        except Exception as e:
            print(f"{Colors.yellow}[!] Error extracting disabled functions: {e}{Colors.reset}")
            return []
    
    def detect_modules(self, phpinfo_content):
        """Detect installed PHP modules"""
        modules = []
        
        # Common dangerous modules
        module_indicators = {
            'mbstring': ['mbstring.ini', 'mbstring extension'],
            'imap': ['imap.ini', 'IMAP', 'imap extension'],
            'libvirt-php': ['libvirt-php.ini', 'libvirt'],
            'gnupg': ['gnupg.ini', 'gnupg extension'],
            'imagick': ['imagick.ini', 'ImageMagick', 'imagick extension'],
            'ffmpeg': ['ffmpeg.ini', 'ffmpeg extension'],
            'redis': ['redis.ini', 'redis extension'],
            'memcached': ['memcached.ini', 'memcached extension'],
            'curl': ['curl.ini', 'curl extension'],
            'openssl': ['openssl.ini', 'openssl extension']
        }
        
        for module, indicators in module_indicators.items():
            for indicator in indicators:
                if indicator.lower() in phpinfo_content.lower():
                    modules.append(module)
                    break
        
        return list(set(modules))  # Remove duplicates
    
    def analyze_functions(self, disabled_functions, detected_modules):
        """Analyze which dangerous functions are available"""
        
        # All dangerous functions to check
        dangerous_functions = [
            'pcntl_alarm', 'pcntl_fork', 'pcntl_waitpid', 'pcntl_wait',
            'pcntl_wifexited', 'pcntl_wifstopped', 'pcntl_wifsignaled',
            'pcntl_wifcontinued', 'pcntl_wexitstatus', 'pcntl_wtermsig',
            'pcntl_wstopsig', 'pcntl_signal', 'pcntl_signal_get_handler',
            'pcntl_signal_dispatch', 'pcntl_get_last_error', 'pcntl_strerror',
            'pcntl_sigprocmask', 'pcntl_sigwaitinfo', 'pcntl_sigtimedwait',
            'pcntl_exec', 'pcntl_getpriority', 'pcntl_setpriority',
            'pcntl_async_signals', 'error_log', 'system', 'exec',
            'shell_exec', 'popen', 'proc_open', 'passthru', 'link',
            'symlink', 'syslog', 'ld', 'mail', 'putenv', 'dl'
        ]
        
        # Module-specific dangerous functions
        module_functions = {
            'mbstring': ['mb_send_mail'],
            'imap': ['imap_open', 'imap_mail'],
            'libvirt': ['libvirt_connect'],
            'gnupg': ['gnupg_init'],
            'ffmpeg': ['ffmpeg_movie']
        }
        
        # Add module-specific functions
        for module in detected_modules:
            if module in module_functions:
                dangerous_functions.extend(module_functions[module])
        
        # Find available (not disabled) dangerous functions
        available_functions = []
        for func in dangerous_functions:
            if func not in disabled_functions:
                available_functions.append(func)
        
        return available_functions, dangerous_functions
    
    def check_bypass_methods(self, detected_modules, available_functions):
        """Check for potential bypass methods"""
        bypass_methods = []
        
        # Check LD_PRELOAD method
        if 'mail' in available_functions and 'putenv' in available_functions:
            bypass_methods.append({
                'name': 'LD_PRELOAD via mail()',
                'description': 'Use putenv() with LD_PRELOAD and mail() to execute arbitrary code',
                'requirements': ['putenv', 'mail'],
                'risk': 'High'
            })
        
        # Check imagick bypass
        if 'imagick' in detected_modules:
            bypass_methods.append({
                'name': 'ImageMagick vulnerability',
                'description': 'Imagick module present - potential for image processing vulnerabilities',
                'requirements': ['imagick module'],
                'risk': 'Medium'
            })
        
        # Check IMAP bypass
        if 'imap' in detected_modules:
            if 'imap_open' in available_functions:
                bypass_methods.append({
                    'name': 'IMAP RCE',
                    'description': 'imap_open can execute commands via rsh/ssh',
                    'requirements': ['imap_open'],
                    'risk': 'High'
                })
        
        # Check PHP-FPM bypass
        fpm_functions = ['stream_socket_sendto', 'stream_socket_client', 'fsockopen']
        available_fpm = [f for f in fpm_functions if f in available_functions]
        if available_fpm:
            bypass_methods.append({
                'name': 'PHP-FPM attack',
                'description': 'Can exploit PHP-FPM via FastCGI protocol',
                'requirements': available_fpm,
                'risk': 'High'
            })
        
        # Check PCNTL functions
        pcntl_functions = [f for f in available_functions if f.startswith('pcntl_')]
        if pcntl_functions:
            bypass_methods.append({
                'name': 'PCNTL process forking',
                'description': 'Can create child processes for code execution',
                'requirements': pcntl_functions[:3],
                'risk': 'Medium'
            })
        
        # Check proc_open for command execution
        if 'proc_open' in available_functions:
            bypass_methods.append({
                'name': 'proc_open execution',
                'description': 'Can execute commands via proc_open with pipes',
                'requirements': ['proc_open'],
                'risk': 'High'
            })
        
        return bypass_methods
    
    def generate_recommendations(self, available_functions, detected_modules, bypass_methods):
        """Generate security recommendations"""
        recommendations = []
        
        if available_functions:
            recommendations.append({
                'title': 'Disable Dangerous Functions',
                'description': f"Add these functions to disable_functions: {', '.join(available_functions[:10])}",
                'priority': 'High'
            })
        
        if detected_modules:
            recommendations.append({
                'title': 'Review Module Usage',
                'description': f"Consider disabling unnecessary modules: {', '.join(detected_modules)}",
                'priority': 'Medium'
            })
        
        if bypass_methods:
            recommendations.append({
                'title': 'Implement Additional Hardening',
                'description': 'Use open_basedir, SELinux, or AppArmor for additional protection',
                'priority': 'High'
            })
        
        if 'putenv' in available_functions and 'mail' in available_functions:
            recommendations.append({
                'title': 'Disable putenv() and mail()',
                'description': 'These functions can be combined for LD_PRELOAD attacks',
                'priority': 'Critical'
            })
        
        return recommendations
    
    def print_banner(self):
        """Print the tool banner"""
        banner = f"""
{Colors.green}                                ,---,     
                                  .'  .' `\   
                                  ,---.'     \  
                                  |   |  .`\  | 
                                  :   : |  '  | 
                                  |   ' '  ;  : 
                                  '   | ;  .  | 
                                  |   | :  |  ' 
                                  '   : | /  ;  
                                  |   | '` ,/   
                                  ;   :  .'     
                                  |   ,.'       
                                  '---'         
{Colors.reset}
        \t\t\t{Colors.blue}Enhanced PHP Security Scanner v2.0{Colors.reset}
        \t\t\t{Colors.orange}Original concept: __c3rb3ru5__, $_SpyD3r_${Colors.reset}
        \t\t\t{Colors.cyan}Enhanced with Python3 & SSL support{Colors.reset}
        """
        print(banner)
    
    def run(self, source):
        """Main execution flow"""
        self.print_banner()
        
        # Fetch PHP info
        phpinfo_content = self.fetch_phpinfo(source)
        
        # Extract disabled functions
        print(f"{Colors.blue}[*] Analyzing PHP configuration...{Colors.reset}")
        disabled_functions = self.extract_disabled_functions(phpinfo_content)
        
        print(f"{Colors.green}[+] Found {len(disabled_functions)} disabled functions{Colors.reset}")
        
        # Detect modules
        detected_modules = self.detect_modules(phpinfo_content)
        if detected_modules:
            print(f"{Colors.green}[+] Detected modules: {', '.join(detected_modules)}{Colors.reset}")
        
        # Analyze available dangerous functions
        available_functions, all_dangerous = self.analyze_functions(disabled_functions, detected_modules)
        
        # Display results
        print(f"\n{Colors.bold}{Colors.yellow}=== Analysis Results ==={Colors.reset}\n")
        
        if available_functions:
            print(f"{Colors.red}[!] Dangerous functions AVAILABLE: {len(available_functions)}{Colors.reset}")
            print(f"{Colors.orange}    {', '.join(available_functions[:20])}{Colors.reset}")
            if len(available_functions) > 20:
                print(f"{Colors.orange}    ... and {len(available_functions) - 20} more{Colors.reset}")
        else:
            print(f"{Colors.green}[+] No dangerous functions found - Good configuration!{Colors.reset}")
        
        # Check bypass methods
        bypass_methods = self.check_bypass_methods(detected_modules, available_functions)
        
        if bypass_methods:
            print(f"\n{Colors.bold}{Colors.red}=== Potential Bypass Methods ==={Colors.reset}")
            for method in bypass_methods:
                print(f"\n{Colors.orange}[!] {method['name']}{Colors.reset}")
                print(f"    {Colors.cyan}Description: {method['description']}{Colors.reset}")
                print(f"    {Colors.yellow}Risk Level: {method['risk']}{Colors.reset}")
                print(f"    {Colors.blue}Requirements: {', '.join(method['requirements'])}{Colors.reset}")
        
        # Generate recommendations
        recommendations = self.generate_recommendations(available_functions, detected_modules, bypass_methods)
        
        if recommendations:
            print(f"\n{Colors.bold}{Colors.green}=== Security Recommendations ==={Colors.reset}")
            for rec in recommendations:
                print(f"\n{Colors.yellow}[{rec['priority']}] {rec['title']}{Colors.reset}")
                print(f"    {Colors.cyan}{rec['description']}{Colors.reset}")
        
        print(f"\n{Colors.bold}{Colors.blue}=== Summary ==={Colors.reset}")
        print(f"Total disabled functions: {len(disabled_functions)}")
        print(f"Available dangerous functions: {len(available_functions)}")
        print(f"Detected modules: {len(detected_modules)}")
        print(f"Potential bypass methods: {len(bypass_methods)}")

def main():
    parser = argparse.ArgumentParser(
        description='PHP Security Scanner - Check disabled functions and bypass vectors',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --url https://example.com/phpinfo.php
  %(prog)s --url https://example.com/phpinfo.php --no-verify-ssl
  %(prog)s --file /path/to/phpinfo.html
  %(prog)s --url https://example.com/phpinfo.php --output report.txt
        """
    )
    
    parser.add_argument("--url", help="PHPinfo URL (http:// or https://)")
    parser.add_argument("--file", help="PHPinfo local file path")
    parser.add_argument("--no-verify-ssl", "--insecure", action="store_true", 
                       help="Disable SSL verification (for self-signed certificates)")
    parser.add_argument("--timeout", type=int, default=10, 
                       help="Request timeout in seconds (default: 10)")
    parser.add_argument("--user-agent", help="Custom User-Agent string")
    parser.add_argument("--output", "-o", help="Save results to file")
    parser.add_argument("--verbose", "-v", action="store_true", 
                       help="Enable verbose output")
    
    args = parser.parse_args()
    
    # Validate input
    if not args.url and not args.file:
        parser.print_help()
        print(f"\n{Colors.red}[-] Error: Either --url or --file is required{Colors.reset}")
        sys.exit(1)
    
    source = args.url if args.url else args.file
    
    # Create scanner instance
    scanner = PHPInfoScanner(
        verify_ssl=not args.no_verify_ssl,
        timeout=args.timeout,
        user_agent=args.user_agent
    )
    
    try:
        # Run scan
        scanner.run(source)
        
        # Save output if requested
        if args.output:
            import io
            from contextlib import redirect_stdout
            
            output_buffer = io.StringIO()
            with redirect_stdout(output_buffer):
                scanner.run(source)
            
            output_content = output_buffer.getvalue()
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output_content)
            print(f"\n{Colors.green}[+] Results saved to: {args.output}{Colors.reset}")
            
    except KeyboardInterrupt:
        print(f"\n{Colors.yellow}[!] Scan interrupted by user{Colors.reset}")
        sys.exit(0)
    except Exception as e:
        print(f"{Colors.red}[-] Unexpected error: {e}{Colors.reset}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()
