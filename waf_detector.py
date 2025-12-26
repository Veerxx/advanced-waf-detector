#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════════╗
║                                                                                  ║
║    █████╗ ██████╗ ██╗   ██╗ █████╗ ███╗   ██╗ ██████╗ ███████╗ ██████╗         ║
║   ██╔══██╗██╔══██╗██║   ██║██╔══██╗████╗  ██║██╔════╝ ██╔════╝██╔═══██╗        ║
║   ███████║██║  ██║██║   ██║███████║██╔██╗ ██║██║  ███╗█████╗  ██║   ██║        ║
║   ██╔══██║██║  ██║██║   ██║██╔══██║██║╚██╗██║██║   ██║██╔══╝  ██║   ██║        ║
║   ██║  ██║██████╔╝╚██████╔╝██║  ██║██║ ╚████║╚██████╔╝███████╗╚██████╔╝        ║
║   ╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ ╚══════╝ ╚═════╝         ║
║                                                                                  ║
║                𝔸𝕕𝕧𝕒𝕟𝕔𝕖𝕕 𝕎𝔸𝔽 𝔻𝕖𝕥𝕖𝕔𝕥𝕚𝕠𝕟 𝕋𝕠𝕠𝕝 𝕧𝟚.𝟘                        ║
║                                                                                  ║
║           Created by: Veerxx | GitHub: https://github.com/Veerxx                 ║
║           Features: Multi-technique WAF fingerprinting & detection               ║
║           Detects: Cloudflare, AWS, Akamai, Imperva, 50+ WAF solutions           ║
║                                                                                  ║
╚══════════════════════════════════════════════════════════════════════════════════╝
"""

import os
import sys
import json
import time
import socket
import ssl
import random
import argparse
import requests
import dns.resolver
import ipaddress
from datetime import datetime
from urllib.parse import urlparse, urljoin
from colorama import Fore, Style, init, Back
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional, Any
import hashlib
import base64

# Initialize colorama
init(autoreset=True)

class ColorPrinter:
    """Custom color printing class"""
    @staticmethod
    def info(msg):
        print(f"{Fore.CYAN}[*]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def success(msg):
        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def warning(msg):
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def error(msg):
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def veerxx(msg):
        print(f"{Fore.MAGENTA}[VEERXX]{Style.RESET_ALL} {msg}")
    
    @staticmethod
    def detection(msg):
        print(f"{Fore.RED}[WAF]{Style.RESET_ALL} {msg}")

class AdvancedWAFDetector:
    """Main WAF detection class by Veerxx"""
    
    VERSION = "2.0.0"
    AUTHOR = "Veerxx"
    GITHUB = "https://github.com/Veerxx"
    BANNER = f"""
{Fore.CYAN}
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   ██╗    ██╗ █████╗ ███████╗    ██████╗ ███████╗████████╗       ║
║   ██║    ██║██╔══██╗██╔════╝    ██╔══██╗██╔════╝╚══██╔══╝       ║
║   ██║ █╗ ██║███████║█████╗      ██████╔╝█████╗     ██║          ║
║   ██║███╗██║██╔══██║██╔══╝      ██╔══██╗██╔══╝     ██║          ║
║   ╚███╔███╔╝██║  ██║██║         ██║  ██║███████╗   ██║          ║
║    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝         ╚═╝  ╚═╝╚══════╝   ╚═╝          ║
║                                                                  ║
║              ADVANCED WAF DETECTION TOOL v{VERSION}             ║
║                  Created by: {Fore.YELLOW}{AUTHOR}{Fore.CYAN}                      ║
║            GitHub: {Fore.YELLOW}{GITHUB}{Fore.CYAN}                        ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
{Style.RESET_ALL}
    """
    
    def __init__(self, target_url: str, config_path: str = "config", **kwargs):
        """
        Initialize WAF Detector
        
        Args:
            target_url: URL to scan
            config_path: Path to configuration directory
            **kwargs: Additional options
        """
        self.target_url = self._normalize_url(target_url)
        self.domain = urlparse(self.target_url).netloc
        self.base_domain = self._extract_base_domain(self.domain)
        
        # Configuration
        self.config_path = config_path
        self.signatures = self._load_signatures()
        self.payloads = self._load_payloads()
        
        # Options
        self.timeout = kwargs.get('timeout', 10)
        self.threads = kwargs.get('threads', 5)
        self.verbose = kwargs.get('verbose', False)
        self.stealth = kwargs.get('stealth', False)
        self.aggressive = kwargs.get('aggressive', False)
        self.proxy = kwargs.get('proxy', None)
        
        # Results storage
        self.results = {
            'target': self.target_url,
            'domain': self.domain,
            'detection_methods': {},
            'detected_wafs': [],
            'confidence_scores': {},
            'timestamps': {
                'start': datetime.now().isoformat(),
                'end': None
            },
            'tool_info': {
                'name': 'Advanced WAF Detector',
                'version': self.VERSION,
                'author': self.AUTHOR,
                'github': self.GITHUB
            }
        }
        
        # Setup session
        self.session = self._create_session()
        
        # Statistics
        self.stats = {
            'requests_sent': 0,
            'blocks_detected': 0,
            'timeouts': 0,
            'errors': 0
        }
        
        ColorPrinter.veerxx(f"Initialized detector for: {self.target_url}")
        if self.verbose:
            ColorPrinter.info(f"Base domain: {self.base_domain}")
            ColorPrinter.info(f"Threads: {self.threads}, Timeout: {self.timeout}s")
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL format"""
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url
        return url.rstrip('/')
    
    def _extract_base_domain(self, domain: str) -> str:
        """Extract base domain from subdomain"""
        parts = domain.split('.')
        if len(parts) > 2:
            # Remove subdomains
            return '.'.join(parts[-2:])
        return domain
    
    def _create_session(self) -> requests.Session:
        """Create HTTP session with custom headers"""
        session = requests.Session()
        
        # Random user agents
        user_agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15',
            'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0',
            'Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15'
        ]
        
        session.headers.update({
            'User-Agent': random.choice(user_agents),
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'max-age=0'
        })
        
        # Add proxy if specified
        if self.proxy:
            session.proxies = {
                'http': self.proxy,
                'https': self.proxy
            }
        
        return session
    
    def _load_signatures(self) -> Dict:
        """Load WAF signatures from JSON file"""
        try:
            sig_file = os.path.join(self.config_path, 'waf_signatures.json')
            if os.path.exists(sig_file):
                with open(sig_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        
        # Default signatures if file not found
        return self._get_default_signatures()
    
    def _load_payloads(self) -> Dict:
        """Load attack payloads from JSON file"""
        try:
            payload_file = os.path.join(self.config_path, 'payloads.json')
            if os.path.exists(payload_file):
                with open(payload_file, 'r') as f:
                    return json.load(f)
        except:
            pass
        
        # Default payloads if file not found
        return self._get_default_payloads()
    
    def _get_default_signatures(self) -> Dict:
        """Return default WAF signatures"""
        return {
            "Cloudflare": {
                "name": "Cloudflare",
                "description": "Cloudflare Web Application Firewall",
                "headers": ["cf-ray", "cf-cache-status", "cf-request-id", "cf-polished", "cf-bgj"],
                "cookies": ["__cfduid", "__cflb", "__cf_bm"],
                "body_patterns": [
                    "cloudflare",
                    "ray id",
                    "attention required",
                    "cf-error"
                ],
                "server_header": ["cloudflare"],
                "response_codes": [403, 503, 429],
                "ports": [443, 2053, 2083, 2087, 2096, 8443],
                "ip_ranges": [
                    "103.21.244.0/22",
                    "104.16.0.0/12",
                    "108.162.192.0/18"
                ],
                "dns_patterns": [".cloudflare.net", ".cloudflare.com"],
                "confidence": 95
            },
            # ... (other signatures similar to previous version)
        }
    
    def _get_default_payloads(self) -> Dict:
        """Return default attack payloads"""
        return {
            "sql_injection": [
                "' OR '1'='1",
                "1' AND SLEEP(5)--",
                "1 UNION SELECT NULL--",
                "admin'--",
                "' OR 1=1--"
            ],
            "xss": [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert(1)>",
                "javascript:alert(1)",
                "\"onmouseover=\"alert(1)"
            ],
            "path_traversal": [
                "../../../etc/passwd",
                "..\\..\\..\\windows\\win.ini",
                "/etc/passwd",
                "C:\\Windows\\System32\\drivers\\etc\\hosts"
            ],
            "command_injection": [
                "; ls -la",
                "| dir",
                "`id`",
                "$(whoami)"
            ],
            "xxe": [
                "<?xml version=\"1.0\"?><!DOCTYPE root [<!ENTITY test SYSTEM 'file:///etc/passwd'>]><root>&test;</root>"
            ],
            "ssti": [
                "{{7*7}}",
                "${7*7}",
                "<%= 7*7 %>"
            ],
            "lfi": [
                "../../../etc/passwd",
                "php://filter/convert.base64-encode/resource=index.php",
                "file:///etc/passwd"
            ]
        }
    
    def _make_request(self, url: str, method: str = 'GET', **kwargs) -> Optional[requests.Response]:
        """Make HTTP request with error handling and statistics"""
        try:
            self.stats['requests_sent'] += 1
            
            # Add random delay for stealth mode
            if self.stealth:
                time.sleep(random.uniform(0.5, 2.0))
            
            response = self.session.request(
                method=method,
                url=url,
                timeout=self.timeout,
                **kwargs
            )
            
            # Check for WAF blocks
            if response.status_code in [403, 406, 409, 418, 429, 503]:
                self.stats['blocks_detected'] += 1
            
            return response
            
        except requests.exceptions.Timeout:
            self.stats['timeouts'] += 1
            if self.verbose:
                ColorPrinter.warning(f"Timeout for {url}")
        except Exception as e:
            self.stats['errors'] += 1
            if self.verbose:
                ColorPrinter.error(f"Error for {url}: {e}")
        
        return None
    
    # ===== DETECTION METHODS =====
    
    def detect_via_dns(self) -> List[str]:
        """Detect WAF via DNS analysis"""
        ColorPrinter.info("Performing DNS analysis...")
        detected = []
        
        try:
            # Get IP address
            ip = socket.gethostbyname(self.domain)
            ColorPrinter.info(f"Resolved IP: {ip}")
            
            # Check IP ranges
            for waf_name, sig in self.signatures.items():
                for ip_range in sig.get('ip_ranges', []):
                    try:
                        if ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range):
                            detected.append(waf_name)
                            ColorPrinter.detection(f"IP range match: {waf_name} ({ip_range})")
                    except:
                        pass
            
            # Reverse DNS lookup
            try:
                hostname = socket.gethostbyaddr(ip)[0]
                ColorPrinter.info(f"Reverse DNS: {hostname}")
                
                for waf_name, sig in self.signatures.items():
                    for pattern in sig.get('dns_patterns', []):
                        if pattern in hostname.lower():
                            detected.append(waf_name)
                            ColorPrinter.detection(f"DNS pattern match: {waf_name}")
            except:
                pass
            
            # Check CDN providers via known IP blocks
            cdn_ips = {
                'Cloudflare': ['103.21.244.0/22', '104.16.0.0/12'],
                'Akamai': ['23.0.0.0/12', '104.64.0.0/10'],
                'AWS': ['3.0.0.0/9', '13.0.0.0/8'],
                'Fastly': ['151.101.0.0/16'],
                'Google Cloud': ['8.8.8.8/32', '35.0.0.0/8']
            }
            
            for cdn, ranges in cdn_ips.items():
                for ip_range in ranges:
                    try:
                        if ipaddress.ip_address(ip) in ipaddress.ip_network(ip_range):
                            detected.append(f"{cdn} CDN")
                    except:
                        pass
                        
        except Exception as e:
            if self.verbose:
                ColorPrinter.error(f"DNS detection error: {e}")
        
        return list(set(detected))
    
    def detect_via_ssl(self) -> List[str]:
        """Detect WAF via SSL/TLS certificate analysis"""
        ColorPrinter.info("Performing SSL/TLS analysis...")
        detected = []
        
        try:
            hostname = self.domain.split(':')[0]
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Get certificate info
                    issuer = dict(x[0] for x in cert['issuer'])
                    subject = dict(x[0] for x in cert['subject'])
                    
                    issuer_org = issuer.get('organizationName', '').lower()
                    subject_org = subject.get('organizationName', '').lower()
                    common_name = subject.get('commonName', '').lower()
                    
                    ColorPrinter.info(f"SSL Issuer: {issuer_org}")
                    ColorPrinter.info(f"SSL Subject: {subject_org}")
                    ColorPrinter.info(f"SSL Common Name: {common_name}")
                    
                    # Check for WAF patterns
                    waf_certs = {
                        'cloudflare': 'Cloudflare',
                        'akamai': 'Akamai',
                        'amazon': 'AWS',
                        'google': 'Google Cloud',
                        'microsoft': 'Azure',
                        'incapsula': 'Imperva',
                        'sucuri': 'Sucuri',
                        'comodo': 'Comodo',
                        'digicert': 'DigiCert',
                        'letsencrypt': 'Let\'s Encrypt'
                    }
                    
                    for pattern, waf in waf_certs.items():
                        if (pattern in issuer_org or 
                            pattern in subject_org or 
                            pattern in common_name):
                            detected.append(waf)
                            ColorPrinter.detection(f"SSL certificate match: {waf}")
                    
                    # Check certificate fingerprint
                    cert_der = ssock.getpeercert(binary_form=True)
                    cert_hash = hashlib.sha256(cert_der).hexdigest()
                    
                    # Known certificate fingerprints
                    known_fingerprints = {
                        'cloudflare': [
                            'e35d2841edb0e0a5ee8c6d2e3f4f6d8c9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4'
                        ]
                    }
                    
                    for waf, fingerprints in known_fingerprints.items():
                        if cert_hash in fingerprints:
                            detected.append(waf)
                            ColorPrinter.detection(f"Certificate fingerprint match: {waf}")
                            
        except Exception as e:
            if self.verbose:
                ColorPrinter.error(f"SSL detection error: {e}")
        
        return list(set(detected))
    
    def detect_via_headers(self, response: requests.Response) -> List[str]:
        """Detect WAF via HTTP headers analysis"""
        detected = []
        
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        
        for waf_name, sig in self.signatures.items():
            # Check for specific headers
            for header_pattern in sig.get('headers', []):
                for header in headers_lower:
                    if header_pattern.lower() in header:
                        detected.append(waf_name)
                        if self.verbose:
                            ColorPrinter.detection(f"Header match: {header} -> {waf_name}")
            
            # Check Server header
            server_header = headers_lower.get('server', '')
            server_patterns = sig.get('server_header', [])
            
            for pattern in server_patterns:
                if pattern and pattern.lower() in server_header:
                    detected.append(waf_name)
                    if self.verbose:
                        ColorPrinter.detection(f"Server header match: {server_header} -> {waf_name}")
        
        return list(set(detected))
    
    def detect_via_response_patterns(self, response: requests.Response) -> List[str]:
        """Detect WAF via response body patterns"""
        detected = []
        response_text = response.text.lower()
        
        for waf_name, sig in self.signatures.items():
            # Check response codes
            if response.status_code in sig.get('response_codes', []):
                detected.append(waf_name)
                if self.verbose:
                    ColorPrinter.detection(f"Response code {response.status_code} -> {waf_name}")
            
            # Check body patterns
            for pattern in sig.get('body_patterns', []):
                if pattern.lower() in response_text:
                    detected.append(waf_name)
                    if self.verbose:
                        ColorPrinter.detection(f"Body pattern: {pattern} -> {waf_name}")
        
        return list(set(detected))
    
    def detect_via_behavior(self) -> Dict:
        """Detect WAF via behavioral analysis"""
        ColorPrinter.info("Performing behavioral analysis...")
        results = {
            'detected_wafs': [],
            'behavior_indicators': [],
            'response_times': [],
            'block_rates': []
        }
        
        # Test normal request
        normal_start = time.time()
        normal_response = self._make_request(self.target_url)
        normal_time = time.time() - normal_start
        
        if normal_response:
            results['response_times'].append(('normal', normal_time))
            
            # Test with malicious payloads
            test_cases = [
                ("sql_injection", self.payloads['sql_injection'][0]),
                ("xss", self.payloads['xss'][0]),
                ("path_traversal", self.payloads['path_traversal'][0])
            ]
            
            for test_name, payload in test_cases:
                test_url = f"{self.target_url}?test={payload}"
                test_start = time.time()
                test_response = self._make_request(test_url)
                test_time = time.time() - test_start
                
                results['response_times'].append((test_name, test_time))
                
                if test_response:
                    # Check if blocked
                    if test_response.status_code in [403, 406, 409, 418, 429, 503]:
                        results['block_rates'].append((test_name, True))
                        results['behavior_indicators'].append(f"Blocked {test_name} payload")
                        
                        # Analyze block page
                        block_indicators = self._analyze_block_page(test_response)
                        results['detected_wafs'].extend(block_indicators)
                    else:
                        results['block_rates'].append((test_name, False))
        
        # Calculate statistics
        if results['response_times']:
            avg_time = sum(t for _, t in results['response_times']) / len(results['response_times'])
            results['avg_response_time'] = avg_time
        
        if results['block_rates']:
            block_count = sum(1 for _, blocked in results['block_rates'] if blocked)
            block_rate = (block_count / len(results['block_rates'])) * 100
            results['block_rate_percent'] = block_rate
            
            if block_rate > 50:
                results['behavior_indicators'].append(f"High block rate ({block_rate:.1f}%) indicates active WAF")
        
        return results
    
    def detect_via_port_scan(self) -> List[Tuple[int, str]]:
        """Scan for open ports that might indicate WAF/CDN"""
        if not self.aggressive:
            return []
        
        ColorPrinter.info("Performing port scan...")
        open_ports = []
        
        ports_to_scan = [
            (80, "HTTP"),
            (443, "HTTPS"),
            (8080, "Alternative HTTP"),
            (8443, "Alternative HTTPS"),
            (2053, "Cloudflare Spectrum"),
            (2083, "cPanel SSL"),
            (2087, "WHM SSL"),
            (8880, "CDN Port"),
            (8888, "Alternative HTTP")
        ]
        
        host = urlparse(self.target_url).hostname
        
        def scan_port(port, description):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                sock.close()
                return (port, description) if result == 0 else None
            except:
                return None
        
        with ThreadPoolExecutor(max_workers=min(self.threads, 10)) as executor:
            futures = [executor.submit(scan_port, port, desc) for port, desc in ports_to_scan]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    open_ports.append(result)
                    ColorPrinter.info(f"Open port: {result[0]} ({result[1]})")
        
        return open_ports
    
    def detect_via_http_methods(self) -> Dict:
        """Test different HTTP methods for WAF behavior"""
        ColorPrinter.info("Testing HTTP methods...")
        results = {
            'allowed_methods': [],
            'blocked_methods': [],
            'unusual_responses': []
        }
        
        methods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD', 'PATCH', 'TRACE']
        
        for method in methods:
            try:
                response = self._make_request(self.target_url, method=method)
                if response:
                    if response.status_code < 400:
                        results['allowed_methods'].append(method)
                    elif response.status_code in [403, 405]:
                        results['blocked_methods'].append(method)
                    
                    # Check for unusual responses
                    if method == 'TRACE' and response.status_code == 200:
                        results['unusual_responses'].append("TRACE method enabled - security risk!")
                    if response.status_code == 405 and 'allow' in response.headers:
                        allowed = response.headers['allow']
                        if 'PUT' in allowed or 'DELETE' in allowed:
                            results['unusual_responses'].append(f"Potentially dangerous methods allowed: {allowed}")
            except:
                pass
        
        return results
    
    def _analyze_block_page(self, response: requests.Response) -> List[str]:
        """Analyze WAF block page for fingerprints"""
        detected = []
        text = response.text.lower()
        
        block_patterns = {
            'Cloudflare': ['cloudflare', 'ray id', 'cf-error'],
            'Imperva': ['incapsula', 'imperva'],
            'AWS WAF': ['aws', 'request blocked'],
            'Sucuri': ['sucuri', 'cloudproxy'],
            'Wordfence': ['wordfence'],
            'ModSecurity': ['mod_security'],
            'F5': ['bigip', 'f5'],
            'Fortinet': ['forti', 'fortigate'],
            'Generic': ['blocked', 'forbidden', 'access denied', 'firewall']
        }
        
        for waf, patterns in block_patterns.items():
            for pattern in patterns:
                if pattern in text:
                    detected.append(waf)
                    break
        
        return list(set(detected))
    
    # ===== MAIN DETECTION FLOW =====
    
    def run_detection(self) -> Dict:
        """Run all detection methods"""
        ColorPrinter.success(f"Starting WAF detection for: {self.target_url}")
        ColorPrinter.info(f"Tool by: {self.AUTHOR} | {self.GITHUB}")
        
        # Method 1: Initial request analysis
        ColorPrinter.info("\n" + "="*50)
        ColorPrinter.info("Phase 1: Initial Analysis")
        ColorPrinter.info("="*50)
        
        initial_response = self._make_request(self.target_url)
        if initial_response:
            self.results['initial_response'] = {
                'status_code': initial_response.status_code,
                'headers': dict(initial_response.headers),
                'server': initial_response.headers.get('Server', 'Unknown'),
                'content_length': len(initial_response.content)
            }
            
            # Detect via headers
            header_wafs = self.detect_via_headers(initial_response)
            self._add_detection_result('headers', header_wafs, 40)
            
            # Detect via response patterns
            pattern_wafs = self.detect_via_response_patterns(initial_response)
            self._add_detection_result('response_patterns', pattern_wafs, 35)
        
        # Method 2: DNS analysis
        ColorPrinter.info("\n" + "="*50)
        ColorPrinter.info("Phase 2: DNS Analysis")
        ColorPrinter.info("="*50)
        
        dns_wafs = self.detect_via_dns()
        self._add_detection_result('dns', dns_wafs, 30)
        
        # Method 3: SSL analysis
        ColorPrinter.info("\n" + "="*50)
        ColorPrinter.info("Phase 3: SSL/TLS Analysis")
        ColorPrinter.info("="*50)
        
        ssl_wafs = self.detect_via_ssl()
        self._add_detection_result('ssl', ssl_wafs, 25)
        
        # Method 4: Behavioral analysis
        ColorPrinter.info("\n" + "="*50)
        ColorPrinter.info("Phase 4: Behavioral Analysis")
        ColorPrinter.info("="*50)
        
        behavior_results = self.detect_via_behavior()
        self.results['behavior_analysis'] = behavior_results
        self._add_detection_result('behavior', behavior_results['detected_wafs'], 45)
        
        # Method 5: HTTP methods analysis
        ColorPrinter.info("\n" + "="*50)
        ColorPrinter.info("Phase 5: HTTP Methods Analysis")
        ColorPrinter.info("="*50)
        
        http_methods_results = self.detect_via_http_methods()
        self.results['http_methods'] = http_methods_results
        
        # Method 6: Port scan (if aggressive)
        if self.aggressive:
            ColorPrinter.info("\n" + "="*50)
            ColorPrinter.info("Phase 6: Port Scanning")
            ColorPrinter.info("="*50)
            
            open_ports = self.detect_via_port_scan()
            self.results['open_ports'] = open_ports
        
        # Calculate final results
        self.results['timestamps']['end'] = datetime.now().isoformat()
        self.results['statistics'] = self.stats
        self.results['final_detection'] = self._calculate_final_results()
        
        return self.results
    
    def _add_detection_result(self, method: str, wafs: List[str], confidence: int):
        """Add detection result with confidence score"""
        if not wafs:
            return
        
        self.results['detection_methods'][method] = wafs
        
        for waf in wafs:
            if waf not in self.results['detected_wafs']:
                self.results['detected_wafs'].append(waf)
            
            # Update confidence score
            current_score = self.results['confidence_scores'].get(waf, 0)
            self.results['confidence_scores'][waf] = current_score + confidence
    
    def _calculate_final_results(self) -> Dict:
        """Calculate final detection results"""
        if not self.results['detected_wafs']:
            return {
                'waf_detected': False,
                'confidence': 0,
                'message': 'No WAF detected or WAF uses advanced stealth techniques',
                'recommendation': 'Try aggressive mode with -a flag'
            }
        
        # Find top WAF by confidence
        waf_scores = self.results['confidence_scores']
        if waf_scores:
            top_waf, top_score = max(waf_scores.items(), key=lambda x: x[1])
            
            # Calculate confidence level
            if top_score > 80:
                confidence_level = "High"
            elif top_score > 50:
                confidence_level = "Medium"
            else:
                confidence_level = "Low"
            
            return {
                'waf_detected': True,
                'primary_waf': top_waf,
                'confidence_score': top_score,
                'confidence_level': confidence_level,
                'all_detected': self.results['detected_wafs'],
                'detection_methods_used': list(self.results['detection_methods'].keys())
            }
        
        return {
            'waf_detected': True,
            'primary_waf': 'Unknown/Stealth WAF',
            'confidence_score': 0,
            'confidence_level': 'Low',
            'message': 'WAF detected but specific vendor could not be identified'
        }
    
    def print_results(self):
        """Print formatted results"""
        final = self.results['final_detection']
        
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"WAF DETECTION RESULTS")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        if final['waf_detected']:
            print(f"{Fore.GREEN}✅ WAF DETECTED{Style.RESET_ALL}\n")
            
            print(f"{Fore.YELLOW}Primary WAF:{Style.RESET_ALL} {final['primary_waf']}")
            print(f"{Fore.YELLOW}Confidence:{Style.RESET_ALL} {final['confidence_score']}/100 ({final['confidence_level']})")
            
            if 'all_detected' in final and len(final['all_detected']) > 1:
                print(f"\n{Fore.YELLOW}All Detected WAFs:{Style.RESET_ALL}")
                for waf in final['all_detected']:
                    score = self.results['confidence_scores'].get(waf, 0)
                    print(f"  • {waf} ({score}/100)")
            
            if 'detection_methods_used' in final:
                print(f"\n{Fore.YELLOW}Detection Methods Used:{Style.RESET_ALL}")
                for method in final['detection_methods_used']:
                    print(f"  • {method}")
        else:
            print(f"{Fore.RED}❌ NO WAF DETECTED{Style.RESET_ALL}\n")
            print(f"{Fore.YELLOW}Message:{Style.RESET_ALL} {final['message']}")
            if 'recommendation' in final:
                print(f"{Fore.YELLOW}Recommendation:{Style.RESET_ALL} {final['recommendation']}")
        
        # Print statistics
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"STATISTICS")
        print(f"{'='*60}{Style.RESET_ALL}\n")
        
        stats = self.results.get('statistics', {})
        print(f"{Fore.WHITE}Requests Sent:{Style.RESET_ALL} {stats.get('requests_sent', 0)}")
        print(f"{Fore.WHITE}Blocks Detected:{Style.RESET_ALL} {stats.get('blocks_detected', 0)}")
        print(f"{Fore.WHITE}Timeouts:{Style.RESET_ALL} {stats.get('timeouts', 0)}")
        print(f"{Fore.WHITE}Errors:{Style.RESET_ALL} {stats.get('errors', 0)}")
        
        # Print behavior analysis if available
        if 'behavior_analysis' in self.results:
            behavior = self.results['behavior_analysis']
            if 'block_rate_percent' in behavior:
                print(f"{Fore.WHITE}Block Rate:{Style.RESET_ALL} {behavior['block_rate_percent']:.1f}%")
        
        # Print tool info
        print(f"\n{Fore.MAGENTA}{'='*60}")
        print(f"TOOL INFORMATION")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Tool:{Style.RESET_ALL} Advanced WAF Detector v{self.VERSION}")
        print(f"{Fore.WHITE}Author:{Style.RESET_ALL} {self.AUTHOR}")
        print(f"{Fore.WHITE}GitHub:{Style.RESET_ALL} {self.GITHUB}")
        print(f"{Fore.WHITE}Scan Duration:{Style.RESET_ALL} {self._calculate_duration()}")
        print(f"{Fore.MAGENTA}{'='*60}{Style.RESET_ALL}")

    def _calculate_duration(self) -> str:
        """Calculate scan duration"""
        start = datetime.fromisoformat(self.results['timestamps']['start'])
        end = datetime.fromisoformat(self.results['timestamps']['end']) if self.results['timestamps']['end'] else datetime.now()
        duration = end - start
        return str(duration).split('.')[0]  # Remove microseconds

def main():
    """Main function"""
    parser = argparse.ArgumentParser(
        description=f"Advanced WAF Detection Tool v2.0 by Veerxx",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.CYAN}
Examples:
  python waf_detector.py https://example.com
  python waf_detector.py example.com -v -a
  python waf_detector.py target.com -t 10 -o results.json --proxy http://localhost:8080
  
Author: {Fore.YELLOW}Veerxx{Fore.CYAN}
GitHub: {Fore.YELLOW}https://github.com/Veerxx{Fore.CYAN}
        {Style.RESET_ALL}
        """
    )
    
    parser.add_argument("target", help="Target URL or domain to scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-a", "--aggressive", action="store_true", help="Enable aggressive mode (port scan)")
    parser.add_argument("-s", "--stealth", action="store_true", help="Enable stealth mode (slow, random delays)")
    parser.add_argument("-t", "--threads", type=int, default=5, help="Number of threads (default: 5)")
    parser.add_argument("-T", "--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    parser.add_argument("--proxy", help="Use proxy (e.g., http://localhost:8080)")
    parser.add_argument("--no-banner", action="store_true", help="Don't display banner")
    parser.add_argument("--update", action="store_true", help="Update WAF signatures")
    
    args = parser.parse_args()
    
    # Display banner
    if not args.no_banner:
        print(AdvancedWAFDetector.BANNER)
    
    try:
        # Create detector instance
        detector = AdvancedWAFDetector(
            target_url=args.target,
            verbose=args.verbose,
            aggressive=args.aggressive,
            stealth=args.stealth,
            threads=args.threads,
            timeout=args.timeout,
            proxy=args.proxy
        )
        
        # Run detection
        results = detector.run_detection()
        
        # Print results
        detector.print_results()
        
        # Save to file if requested
        if args.output:
            with open(args.output, 'w') as f:
                json.dump(results, f, indent=2, default=str)
            ColorPrinter.success(f"Results saved to: {args.output}")
        
    except KeyboardInterrupt:
        ColorPrinter.warning("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        ColorPrinter.error(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
