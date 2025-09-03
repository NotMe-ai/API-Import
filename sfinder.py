#!/usr/bin/env python3
"""
SecretFinder - A tool to detect hardcoded secrets, credentials, and sensitive information in codebases.

This script scans through files in a directory (or git repository) to identify potential
security risks such as:
- API keys and tokens
- Database credentials
- Private keys and certificates
- Passwords and authentication tokens
- Cloud service credentials
- And other sensitive information patterns
"""

import os
import re
import sys
import argparse
import json
import hashlib
from pathlib import Path
from typing import List, Dict, Set, Tuple
from dataclasses import dataclass, asdict
import fnmatch

@dataclass
class SecretMatch:
    """Represents a found secret or sensitive information"""
    file_path: str
    line_number: int
    line_content: str
    pattern_name: str
    match_text: str
    confidence: str  # HIGH, MEDIUM, LOW
    description: str

class SecretPatterns:
    """Contains all the regex patterns for detecting secrets"""
    
    def __init__(self):
        self.patterns = {
            # API Keys and Tokens
            'aws_access_key': {
                'pattern': r'AKIA[0-9A-Z]{16}',
                'description': 'AWS Access Key ID',
                'confidence': 'HIGH'
            },
            'aws_secret_key': {
                'pattern': r'[A-Za-z0-9/+=]{40}',
                'description': 'AWS Secret Access Key',
                'confidence': 'MEDIUM'
            },
            'github_token': {
                'pattern': r'ghp_[A-Za-z0-9]{36}',
                'description': 'GitHub Personal Access Token',
                'confidence': 'HIGH'
            },
            'github_oauth': {
                'pattern': r'gho_[A-Za-z0-9]{36}',
                'description': 'GitHub OAuth Access Token',
                'confidence': 'HIGH'
            },
            'slack_token': {
                'pattern': r'xox[baprs]-[A-Za-z0-9-]+',
                'description': 'Slack Token',
                'confidence': 'HIGH'
            },
            'google_api_key': {
                'pattern': r'AIza[0-9A-Za-z\\-_]{35}',
                'description': 'Google API Key',
                'confidence': 'HIGH'
            },
            'azure_client_secret': {
                'pattern': r'[A-Za-z0-9~._-]{34}',
                'description': 'Azure Client Secret',
                'confidence': 'LOW'
            },
            'stripe_key': {
                'pattern': r'sk_live_[A-Za-z0-9]{24}',
                'description': 'Stripe Live Secret Key',
                'confidence': 'HIGH'
            },
            'mailgun_api_key': {
                'pattern': r'key-[A-Za-z0-9]{32}',
                'description': 'Mailgun API Key',
                'confidence': 'HIGH'
            },
            'twilio_api_key': {
                'pattern': r'SK[A-Za-z0-9]{32}',
                'description': 'Twilio API Key',
                'confidence': 'HIGH'
            },
            
            # Database and Connection Strings
            'mysql_connection': {
                'pattern': r'mysql://[^\s]*:[^\s]*@[^\s]*',
                'description': 'MySQL Connection String',
                'confidence': 'HIGH'
            },
            'postgres_connection': {
                'pattern': r'postgres://[^\s]*:[^\s]*@[^\s]*',
                'description': 'PostgreSQL Connection String',
                'confidence': 'HIGH'
            },
            'mongodb_connection': {
                'pattern': r'mongodb://[^\s]*:[^\s]*@[^\s]*',
                'description': 'MongoDB Connection String',
                'confidence': 'HIGH'
            },
            
            # Private Keys and Certificates
            'private_key': {
                'pattern': r'-----BEGIN [A-Z ]+PRIVATE KEY-----',
                'description': 'Private Key',
                'confidence': 'HIGH'
            },
            'rsa_private_key': {
                'pattern': r'-----BEGIN RSA PRIVATE KEY-----',
                'description': 'RSA Private Key',
                'confidence': 'HIGH'
            },
            'ssh_private_key': {
                'pattern': r'-----BEGIN OPENSSH PRIVATE KEY-----',
                'description': 'OpenSSH Private Key',
                'confidence': 'HIGH'
            },
            
            # Generic Patterns (lower confidence)
            'password_assignment': {
                'pattern': r'(?i)(password|pwd|pass)\s*[=:]\s*["\'][^"\'\s]{6,}["\']',
                'description': 'Password Assignment',
                'confidence': 'MEDIUM'
            },
            'api_key_assignment': {
                'pattern': r'(?i)(api[_-]?key|apikey|access[_-]?key)\s*[=:]\s*["\'][^"\'\s]{8,}["\']',
                'description': 'API Key Assignment',
                'confidence': 'MEDIUM'
            },
            'secret_assignment': {
                'pattern': r'(?i)(secret|token)\s*[=:]\s*["\'][^"\'\s]{8,}["\']',
                'description': 'Secret/Token Assignment',
                'confidence': 'MEDIUM'
            },
            'bearer_token': {
                'pattern': r'Bearer\s+[A-Za-z0-9\-._~+/]+=*',
                'description': 'Bearer Token',
                'confidence': 'MEDIUM'
            },
            
            # High entropy strings (base64-like)
            'high_entropy_string': {
                'pattern': r'[A-Za-z0-9+/]{40,}={0,2}',
                'description': 'High Entropy String (possible secret)',
                'confidence': 'LOW'
            }
        }
    
    def get_patterns(self) -> Dict[str, Dict]:
        return self.patterns

class SecretFinder:
    """Main class for finding secrets in codebases"""
    
    def __init__(self, ignore_patterns: List[str] = None):
        self.patterns = SecretPatterns()
        self.ignore_patterns = ignore_patterns or [
            '*.git/*', '*.git\\*',
            '*node_modules/*', '*node_modules\\*',
            '*.venv/*', '*.venv\\*',
            '*__pycache__/*', '*__pycache__\\*',
            '*.pyc', '*.pyo',
            '*.log',
            '*.tmp', '*.temp',
            '*dist/*', '*dist\\*',
            '*build/*', '*build\\*',
            '*.exe', '*.dll', '*.so',
            '*.jpg', '*.jpeg', '*.png', '*.gif', '*.bmp',
            '*.pdf', '*.doc', '*.docx'
        ]
        self.found_secrets: List[SecretMatch] = []
    
    def should_ignore_file(self, file_path: str) -> bool:
        """Check if file should be ignored based on patterns"""
        for pattern in self.ignore_patterns:
            if fnmatch.fnmatch(file_path, pattern) or fnmatch.fnmatch(os.path.basename(file_path), pattern):
                return True
        return False
    
    def is_text_file(self, file_path: str) -> bool:
        """Check if file is likely a text file"""
        try:
            with open(file_path, 'rb') as f:
                chunk = f.read(1024)
                if b'\0' in chunk:
                    return False
            return True
        except:
            return False
    
    def scan_file(self, file_path: str) -> List[SecretMatch]:
        """Scan a single file for secrets"""
        matches = []
        
        if self.should_ignore_file(file_path) or not self.is_text_file(file_path):
            return matches
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
                for line_num, line in enumerate(lines, 1):
                    line = line.strip()
                    if not line or line.startswith('#') or line.startswith('//'):
                        continue
                    
                    for pattern_name, pattern_info in self.patterns.get_patterns().items():
                        pattern = pattern_info['pattern']
                        confidence = pattern_info['confidence']
                        description = pattern_info['description']
                        
                        regex_matches = re.finditer(pattern, line, re.IGNORECASE)
                        for match in regex_matches:
                            # Additional filtering for high entropy strings
                            if pattern_name == 'high_entropy_string':
                                if not self._is_likely_secret(match.group()):
                                    continue
                            
                            secret_match = SecretMatch(
                                file_path=file_path,
                                line_number=line_num,
                                line_content=line,
                                pattern_name=pattern_name,
                                match_text=match.group(),
                                confidence=confidence,
                                description=description
                            )
                            matches.append(secret_match)
        
        except Exception as e:
            print(f"Error reading file {file_path}: {e}")
        
        return matches
    
    def _is_likely_secret(self, text: str) -> bool:
        """Additional filtering for high entropy strings"""
        # Skip if too short or too long
        if len(text) < 20 or len(text) > 100:
            return False
        
        # Skip common patterns that are unlikely to be secrets
        if any(pattern in text.lower() for pattern in [
            'lorem', 'ipsum', 'example', 'test', 'sample',
            'abcdef', '123456', 'qwerty'
        ]):
            return False
        
        # Check entropy
        entropy = self._calculate_entropy(text)
        return entropy > 4.5  # Threshold for high entropy
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string"""
        if not text:
            return 0
        
        import math
        entropy = 0
        char_counts = {}
        
        # Count character frequencies
        for char in text:
            char_counts[char] = char_counts.get(char, 0) + 1
        
        # Calculate entropy
        text_len = len(text)
        for count in char_counts.values():
            p = count / text_len
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def scan_directory(self, directory: str) -> List[SecretMatch]:
        """Scan all files in a directory recursively"""
        all_matches = []
        
        for root, dirs, files in os.walk(directory):
            # Skip ignored directories
            dirs[:] = [d for d in dirs if not any(
                fnmatch.fnmatch(os.path.join(root, d), pattern) 
                for pattern in self.ignore_patterns
            )]
            
            for file in files:
                file_path = os.path.join(root, file)
                matches = self.scan_file(file_path)
                all_matches.extend(matches)
        
        self.found_secrets.extend(all_matches)
        return all_matches
    
    def generate_report(self, output_format: str = 'text') -> str:
        """Generate a report of found secrets"""
        if output_format == 'json':
            return json.dumps([asdict(secret) for secret in self.found_secrets], indent=2)
        
        # Text format
        report = []
        report.append("=" * 80)
        report.append("SECRET FINDER REPORT")
        report.append("=" * 80)
        report.append(f"Total secrets found: {len(self.found_secrets)}")
        report.append("")
        
        # Group by confidence level
        high_confidence = [s for s in self.found_secrets if s.confidence == 'HIGH']
        medium_confidence = [s for s in self.found_secrets if s.confidence == 'MEDIUM']
        low_confidence = [s for s in self.found_secrets if s.confidence == 'LOW']
        
        for confidence_level, secrets in [
            ('HIGH CONFIDENCE FINDINGS', high_confidence),
            ('MEDIUM CONFIDENCE FINDINGS', medium_confidence),
            ('LOW CONFIDENCE FINDINGS', low_confidence)
        ]:
            if secrets:
                report.append(f"\n{confidence_level}:")
                report.append("-" * len(confidence_level))
                
                for secret in secrets:
                    report.append(f"\nFile: {secret.file_path}")
                    report.append(f"Line: {secret.line_number}")
                    report.append(f"Type: {secret.description}")
                    report.append(f"Pattern: {secret.pattern_name}")
                    report.append(f"Match: {secret.match_text[:100]}...")
                    report.append(f"Context: {secret.line_content[:100]}...")
                    report.append("-" * 40)
        
        return "\n".join(report)

def main():
    parser = argparse.ArgumentParser(
        description="Find hardcoded secrets and sensitive information in codebases"
    )
    parser.add_argument(
        'path',
        help='Path to directory or file to scan'
    )
    parser.add_argument(
        '--output', '-o',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)'
    )
    parser.add_argument(
        '--output-file', '-f',
        help='Save report to file instead of printing to stdout'
    )
    parser.add_argument(
        '--ignore',
        action='append',
        help='Additional file patterns to ignore (can be used multiple times)'
    )
    parser.add_argument(
        '--confidence',
        choices=['HIGH', 'MEDIUM', 'LOW'],
        help='Only show findings with specified confidence level or higher'
    )
    
    args = parser.parse_args()
    
    # Validate path
    if not os.path.exists(args.path):
        print(f"Error: Path '{args.path}' does not exist")
        sys.exit(1)
    
    # Initialize scanner
    ignore_patterns = args.ignore or []
    scanner = SecretFinder(ignore_patterns=ignore_patterns)
    
    print(f"Scanning '{args.path}' for secrets...")
    
    # Scan
    if os.path.isfile(args.path):
        matches = scanner.scan_file(args.path)
        scanner.found_secrets.extend(matches)
    else:
        matches = scanner.scan_directory(args.path)
    
    # Filter by confidence if specified
    if args.confidence:
        confidence_levels = {'HIGH': 3, 'MEDIUM': 2, 'LOW': 1}
        min_level = confidence_levels[args.confidence]
        scanner.found_secrets = [
            s for s in scanner.found_secrets 
            if confidence_levels[s.confidence] >= min_level
        ]
    
    # Generate report
    report = scanner.generate_report(args.output)
    
    # Output report
    if args.output_file:
        with open(args.output_file, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"Report saved to: {args.output_file}")
    else:
        print(report)
    
    # Return appropriate exit code
    if scanner.found_secrets:
        print(f"\nFound {len(scanner.found_secrets)} potential secrets!")
        sys.exit(1)
    else:
        print("\nNo secrets found.")
        sys.exit(0)

if __name__ == "__main__":
    main()
