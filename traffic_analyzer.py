#!/usr/bin/env python3
"""
Traffic analysis functionality for NaptProxy
"""
import re
import logging
import time
import json
import base64
import urllib.parse
from collections import defaultdict, deque

logger = logging.getLogger("NaptProxy.TrafficAnalyzer")

class TrafficAnalyzer:
    def __init__(self, max_log_entries=1000):
        """
        Initialize the traffic analyzer
        
        Args:
            max_log_entries (int): Maximum number of transaction logs to keep
        """
        self.max_log_entries = max_log_entries
        self.transactions = deque(maxlen=max_log_entries)
        self.current_transaction = {}
        self.stats = {
            'total_requests': 0,
            'total_responses': 0,
            'total_bytes_in': 0,
            'total_bytes_out': 0,
            'request_methods': defaultdict(int),
            'response_codes': defaultdict(int),
            'vulnerability_patterns': defaultdict(int),
            'top_hosts': defaultdict(int),
            'start_time': time.time()
        }
        
        # Common vulnerability scanner patterns
        self.vuln_patterns = {
            'sql_injection': [
                rb"'((\s+)|(%20))(or|and)((\s+)|(%20))'?[=<>]",
                rb"(union)((\s+)|(%20))(select|all)((\s+)|(%20))",
                rb";\s*drop\s+table",
                rb"--[^\r\n]*"
            ],
            'xss': [
                rb"<script[^>]*>",
                rb"javascript:",
                rb"onerror=",
                rb"onload=",
                rb"eval\(",
                rb"document\.cookie"
            ],
            'path_traversal': [
                rb"\.\.\/",
                rb"%2e%2e%2f",
                rb"\.\.\\",
                rb"%2e%2e%5c"
            ],
            'command_injection': [
                rb";\s*[a-zA-Z]+\s+",
                rb"\|\s*[a-zA-Z]+\s+",
                rb"`[^`]*`"
            ],
            'lfi_rfi': [
                rb"=https?:\/\/",
                rb"=ftp:\/\/",
                rb"=(ht|f)tp",
                rb"=\/etc\/passwd",
                rb"=c:\\windows\\system32"
            ],
            'scanner_signatures': [
                rb"nessus",
                rb"acunetix",
                rb"nikto",
                rb"nmap",
                rb"openvas",
                rb"user-agent:\s*(gobuster|dirbuster|wfuzz|zap|sqlmap)",
                rb"burpsuite",
                rb"owasp"
            ],
            'nosql_injection': [
                rb"\{\$where:",
                rb"\{\$gt:",
                rb"\{\$ne:"
            ]
        }
    
    def add_request(self, client_address, request_data):
        """
        Add a new client request to track
        
        Args:
            client_address (tuple): Client address (host, port)
            request_data (bytes): Initial request data
        """
        # Initialize a new transaction
        self.current_transaction = {
            'client_address': f"{client_address[0]}:{client_address[1]}",
            'timestamp': time.time(),
            'request': {
                'raw': base64.b64encode(request_data).decode('utf-8'),
                'method': None,
                'url': None,
                'headers': {},
                'size': len(request_data)
            },
            'response': {
                'raw': None,
                'status_code': None,
                'headers': {},
                'size': 0
            },
            'vulnerabilities': [],
            'duration': 0
        }
        
        # Parse request method, URL and headers
        try:
            lines = request_data.split(b'\r\n')
            first_line = lines[0].decode('utf-8', 'ignore')
            parts = first_line.split(' ')
            
            if len(parts) >= 3:
                method = parts[0]
                url = parts[1]
                
                self.current_transaction['request']['method'] = method
                self.current_transaction['request']['url'] = url
                
                # Update stats
                self.stats['request_methods'][method] += 1
                self.stats['total_requests'] += 1
                self.stats['total_bytes_in'] += len(request_data)
                
                # Extract host from headers or URL
                host = None
                for i in range(1, len(lines)):
                    if not lines[i]:
                        break
                    
                    try:
                        header_line = lines[i].decode('utf-8', 'ignore')
                        if ':' in header_line:
                            name, value = header_line.split(':', 1)
                            name = name.strip().lower()
                            value = value.strip()
                            self.current_transaction['request']['headers'][name] = value
                            
                            if name == 'host':
                                host = value
                    except:
                        pass
                
                if host:
                    self.stats['top_hosts'][host] += 1
                
                # Check for vulnerability patterns
                self.check_vulnerability_patterns(request_data)
        
        except Exception as e:
            logger.error(f"Error parsing request: {str(e)}")
    
    def add_request_data(self, data):
        """
        Add additional request data (for streaming requests)
        
        Args:
            data (bytes): Additional request data
        """
        if self.current_transaction and 'request' in self.current_transaction:
            self.current_transaction['request']['size'] += len(data)
            self.stats['total_bytes_in'] += len(data)
            
            # Check for vulnerability patterns in new data
            self.check_vulnerability_patterns(data)
    
    def add_response_data(self, data):
        """
        Add response data
        
        Args:
            data (bytes): Response data
        """
        if self.current_transaction and 'response' in self.current_transaction:
            if self.current_transaction['response']['raw'] is None:
                self.current_transaction['response']['raw'] = base64.b64encode(data).decode('utf-8')
                
                # Parse status code and headers from response
                try:
                    lines = data.split(b'\r\n')
                    first_line = lines[0].decode('utf-8', 'ignore')
                    parts = first_line.split(' ')
                    
                    if len(parts) >= 3:
                        status_code = parts[1]
                        self.current_transaction['response']['status_code'] = status_code
                        self.stats['response_codes'][status_code] += 1
                    
                    for i in range(1, len(lines)):
                        if not lines[i]:
                            break
                        
                        try:
                            header_line = lines[i].decode('utf-8', 'ignore')
                            if ':' in header_line:
                                name, value = header_line.split(':', 1)
                                name = name.strip().lower()
                                value = value.strip()
                                self.current_transaction['response']['headers'][name] = value
                        except:
                            pass
                
                except Exception as e:
                    logger.error(f"Error parsing response: {str(e)}")
            
            self.current_transaction['response']['size'] += len(data)
            self.stats['total_bytes_out'] += len(data)
            self.stats['total_responses'] += 1
    
    def complete_transaction(self, request_buffer, response_buffer):
        """
        Complete a transaction and add it to the log
        
        Args:
            request_buffer (bytes): Complete request buffer
            response_buffer (bytes): Complete response buffer
        """
        if self.current_transaction:
            self.current_transaction['duration'] = time.time() - self.current_transaction['timestamp']
            self.transactions.append(self.current_transaction)
            self.current_transaction = {}
    
    def check_vulnerability_patterns(self, data):
        """
        Check for known vulnerability scanning patterns
        
        Args:
            data (bytes): Data to check
        """
        for vuln_type, patterns in self.vuln_patterns.items():
            for pattern in patterns:
                matches = re.findall(pattern, data, re.IGNORECASE)
                if matches:
                    self.stats['vulnerability_patterns'][vuln_type] += len(matches)
                    
                    if self.current_transaction:
                        self.current_transaction['vulnerabilities'].append({
                            'type': vuln_type,
                            'pattern': pattern.decode('utf-8', 'ignore'),
                            'matches': len(matches)
                        })
    
    def get_stats(self):
        """
        Get current statistics
        
        Returns:
            dict: Current traffic statistics
        """
        # Calculate uptime
        uptime = time.time() - self.stats['start_time']
        
        return {
            'total_requests': self.stats['total_requests'],
            'total_responses': self.stats['total_responses'],
            'total_bytes_in': self.stats['total_bytes_in'],
            'total_bytes_out': self.stats['total_bytes_out'],
            'request_methods': dict(self.stats['request_methods']),
            'response_codes': dict(self.stats['response_codes']),
            'vulnerability_patterns': dict(self.stats['vulnerability_patterns']),
            'top_hosts': dict(sorted(self.stats['top_hosts'].items(), key=lambda x: x[1], reverse=True)[:10]),
            'uptime': uptime,
            'requests_per_second': self.stats['total_requests'] / uptime if uptime > 0 else 0
        }
    
    def get_transactions(self, limit=100, offset=0, filter_type=None, filter_value=None):
        """
        Get transaction logs with optional filtering
        
        Args:
            limit (int): Maximum number of transactions to return
            offset (int): Offset for pagination
            filter_type (str): Type of filter to apply ('method', 'status', 'vulnerability', 'host')
            filter_value (str): Value to filter by
            
        Returns:
            list: Filtered transaction logs
        """
        filtered_transactions = list(self.transactions)
        
        # Apply filters
        if filter_type and filter_value:
            if filter_type == 'method':
                filtered_transactions = [t for t in filtered_transactions 
                                        if t.get('request', {}).get('method') == filter_value]
            elif filter_type == 'status':
                filtered_transactions = [t for t in filtered_transactions 
                                        if t.get('response', {}).get('status_code') == filter_value]
            elif filter_type == 'vulnerability':
                filtered_transactions = [t for t in filtered_transactions 
                                        if any(v.get('type') == filter_value for v in t.get('vulnerabilities', []))]
            elif filter_type == 'host':
                filtered_transactions = [t for t in filtered_transactions 
                                        if filter_value in t.get('request', {}).get('headers', {}).get('host', '')]
        
        # Apply pagination
        start = min(offset, len(filtered_transactions))
        end = min(start + limit, len(filtered_transactions))
        
        return filtered_transactions[start:end]
    
    def get_vulnerability_summary(self):
        """
        Get a summary of detected vulnerabilities
        
        Returns:
            dict: Vulnerability summary
        """
        vuln_summary = {}
        
        for vuln_type, count in self.stats['vulnerability_patterns'].items():
            # Count transactions with this vulnerability type
            transactions_count = sum(1 for t in self.transactions 
                                    if any(v.get('type') == vuln_type for v in t.get('vulnerabilities', [])))
            
            vuln_summary[vuln_type] = {
                'total_matches': count,
                'transactions_count': transactions_count,
                'description': self.get_vulnerability_description(vuln_type)
            }
        
        return vuln_summary
    
    def get_vulnerability_description(self, vuln_type):
        """
        Get description for vulnerability type
        
        Args:
            vuln_type (str): Vulnerability type
            
        Returns:
            str: Description of the vulnerability
        """
        descriptions = {
            'sql_injection': 'SQL Injection attempts that could extract or manipulate database data',
            'xss': 'Cross-Site Scripting attempts that could execute malicious scripts',
            'path_traversal': 'Directory traversal attempts that could access unauthorized files',
            'command_injection': 'Command injection attempts that could execute arbitrary commands',
            'lfi_rfi': 'Local/Remote File Inclusion attempts that could include malicious files',
            'scanner_signatures': 'Known vulnerability scanner signatures or user-agents',
            'nosql_injection': 'NoSQL Injection attempts that could manipulate NoSQL databases'
        }
        
        return descriptions.get(vuln_type, 'Unknown vulnerability type')
