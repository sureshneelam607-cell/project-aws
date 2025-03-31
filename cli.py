#!/usr/bin/env python3
"""
Command-line interface for NaptProxy
"""
import os
import sys
import signal
import logging
import argparse
import threading
import time
from proxy_server import ProxyServer
from web_interface import start_web_interface
from config import Config

logger = logging.getLogger("NaptProxy.CLI")

class CLI:
    def __init__(self):
        """Initialize the CLI"""
        self.config = Config()
        self.proxy_server = None
        self.web_thread = None
        self.is_running = False
    
    def parse_arguments(self):
        """Parse command line arguments"""
        parser = argparse.ArgumentParser(description='NaptProxy - A vulnerability scanner traffic proxy server')
        
        # Proxy configuration
        parser.add_argument('--proxy-host', type=str,
                            help='Host for the proxy server')
        parser.add_argument('--proxy-port', type=int,
                            help='Port for the proxy server')
        
        # Web interface configuration
        parser.add_argument('--web-host', type=str,
                            help='Host for the web interface')
        parser.add_argument('--web-port', type=int,
                            help='Port for the web interface')
        parser.add_argument('--no-web', action='store_true',
                            help='Disable web interface')
        
        # Logging configuration
        parser.add_argument('--log-level', type=str, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                            help='Set the logging level')
        parser.add_argument('--log-file', type=str,
                            help='File to save logs')
        
        # SSL interception
        parser.add_argument('--intercept-ssl', action='store_true',
                            help='Enable SSL/TLS interception (requires CA certificate)')
        parser.add_argument('--ca-cert', type=str,
                            help='Path to CA certificate')
        parser.add_argument('--ca-key', type=str,
                            help='Path to CA private key')
        
        # Configuration
        parser.add_argument('--config', type=str,
                            help='Path to configuration file')
        
        # Commands
        subparsers = parser.add_subparsers(dest='command', help='Command to execute')
        
        # Start command
        start_parser = subparsers.add_parser('start', help='Start the proxy server')
        
        # Stop command
        stop_parser = subparsers.add_parser('stop', help='Stop the proxy server')
        
        # Status command
        status_parser = subparsers.add_parser('status', help='Show proxy server status')
        
        # Generate CA command
        ca_parser = subparsers.add_parser('generate-ca', help='Generate CA certificate and key')
        ca_parser.add_argument('--ca-name', type=str, default='NaptProxy CA',
                              help='CA name (default: NaptProxy CA)')
        ca_parser.add_argument('--ca-dir', type=str, default='ca',
                              help='Directory to save CA certificate and key (default: ca)')
        
        return parser.parse_args()
    
    def start(self, args):
        """Start the proxy server and web interface"""
        # Update configuration from command line arguments
        self.update_config_from_args(args)
        
        # Set up logging
        log_level = getattr(logging, self.config.get('logging', 'level', 'INFO'))
        log_file = self.config.get('logging', 'file', 'naptyproxy.log')
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        
        # Create and configure proxy server
        proxy_host = self.config.get('proxy', 'host', '0.0.0.0')
        proxy_port = self.config.get('proxy', 'port', 8000)
        buffer_size = self.config.get('proxy', 'buffer_size', 8192)
        timeout = self.config.get('proxy', 'timeout', 60)
        max_connections = self.config.get('proxy', 'max_connections', 100)
        intercept_ssl = self.config.get('ssl', 'intercept', False)
        ca_cert = self.config.get('ssl', 'ca_cert', 'ca/ca.crt')
        ca_key = self.config.get('ssl', 'ca_key', 'ca/ca.key')
        
        self.proxy_server = ProxyServer(
            host=proxy_host,
            port=proxy_port,
            buffer_size=buffer_size,
            timeout=timeout,
            max_connections=max_connections,
            intercept_ssl=intercept_ssl,
            ca_cert=ca_cert,
            ca_key=ca_key
        )
        
        # Start proxy server in a separate thread
        proxy_thread = threading.Thread(target=self.proxy_server.start)
        proxy_thread.daemon = True
        proxy_thread.start()
        
        logger.info(f"Proxy server started on {proxy_host}:{proxy_port}")
        
        # Start web interface if enabled
        web_enabled = self.config.get('web_interface', 'enable', True)
        if web_enabled and not args.no_web:
            web_host = self.config.get('web_interface', 'host', '0.0.0.0')
            web_port = self.config.get('web_interface', 'port', 5000)
            
            self.web_thread = threading.Thread(
                target=start_web_interface,
                args=(web_host, web_port, self.proxy_server)
            )
            self.web_thread.daemon = True
            self.web_thread.start()
            
            logger.info(f"Web interface started on http://{web_host}:{web_port}")
        
        self.is_running = True
        
        # Handle keyboard interrupt
        signal.signal(signal.SIGINT, self.handle_signal)
        signal.signal(signal.SIGTERM, self.handle_signal)
        
        # Keep main thread alive
        try:
            while self.is_running:
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop()
    
    def stop(self):
        """Stop the proxy server"""
        if self.proxy_server:
            self.proxy_server.stop()
            logger.info("Proxy server stopped")
        
        self.is_running = False
    
    def status(self):
        """Show proxy server status"""
        if self.proxy_server:
            status = self.proxy_server.get_status()
            
            print("\nNaptProxy Status:")
            print("=================")
            print(f"Running: {'Yes' if status['running'] else 'No'}")
            print(f"Proxy Address: {status['host']}:{status['port']}")
            print(f"SSL Interception: {'Enabled' if status['intercept_ssl'] else 'Disabled'}")
            print(f"Active Connections: {status['connections']}/{status['max_connections']}")
            
            if 'traffic_stats' in status:
                stats = status['traffic_stats']
                print("\nTraffic Statistics:")
                print("------------------")
                print(f"Total Requests: {stats['total_requests']}")
                print(f"Total Responses: {stats['total_responses']}")
                print(f"Data In: {self.format_size(stats['total_bytes_in'])}")
                print(f"Data Out: {self.format_size(stats['total_bytes_out'])}")
                print(f"Uptime: {self.format_duration(stats['uptime'])}")
                print(f"Requests/sec: {stats['requests_per_second']:.2f}")
                
                print("\nRequest Methods:")
                for method, count in stats['request_methods'].items():
                    print(f"  {method}: {count}")
                
                print("\nResponse Codes:")
                for code, count in stats['response_codes'].items():
                    print(f"  {code}: {count}")
                
                print("\nVulnerability Patterns:")
                for vuln, count in stats['vulnerability_patterns'].items():
                    print(f"  {vuln}: {count}")
                
                print("\nTop Hosts:")
                for host, count in stats['top_hosts'].items():
                    print(f"  {host}: {count}")
            
            print("\nWeb Interface:")
            web_enabled = self.config.get('web_interface', 'enable', True)
            if web_enabled:
                web_host = self.config.get('web_interface', 'host', '0.0.0.0')
                web_port = self.config.get('web_interface', 'port', 5000)
                print(f"  URL: http://{web_host}:{web_port}")
            else:
                print("  Disabled")
        else:
            print("Proxy server is not running")
    
    def generate_ca(self, args):
        """Generate CA certificate and key"""
        from ca.generate_ca import generate_ca_certificate
        
        ca_name = args.ca_name
        ca_dir = args.ca_dir
        
        try:
            cert_path, key_path = generate_ca_certificate(ca_name, ca_dir)
            
            print(f"\nCA Certificate generated successfully:")
            print(f"  Certificate: {cert_path}")
            print(f"  Private Key: {key_path}")
            print("\nImportant: You need to install this certificate in your browser to intercept HTTPS traffic.")
            print("For more information on installing CA certificates, see the documentation.")
            
            # Update config to use new certificates
            self.config.set('ssl', 'ca_cert', cert_path)
            self.config.set('ssl', 'ca_key', key_path)
            self.config.save_config()
            
        except Exception as e:
            logger.error(f"Error generating CA certificate: {str(e)}")
            print(f"Error: {str(e)}")
    
    def handle_signal(self, signum, frame):
        """Handle signals for graceful shutdown"""
        logger.info(f"Received signal {signum}, shutting down")
        self.stop()
    
    def update_config_from_args(self, args):
        """Update configuration from command line arguments"""
        # Custom config file
        if args.config:
            self.config = Config(args.config)
        
        # Proxy settings
        if args.proxy_host:
            self.config.set('proxy', 'host', args.proxy_host)
        if args.proxy_port:
            self.config.set('proxy', 'port', args.proxy_port)
        
        # Web interface settings
        if args.web_host:
            self.config.set('web_interface', 'host', args.web_host)
        if args.web_port:
            self.config.set('web_interface', 'port', args.web_port)
        if args.no_web:
            self.config.set('web_interface', 'enable', False)
        
        # Logging settings
        if args.log_level:
            self.config.set('logging', 'level', args.log_level)
        if args.log_file:
            self.config.set('logging', 'file', args.log_file)
        
        # SSL interception settings
        if args.intercept_ssl:
            self.config.set('ssl', 'intercept', True)
        if args.ca_cert:
            self.config.set('ssl', 'ca_cert', args.ca_cert)
        if args.ca_key:
            self.config.set('ssl', 'ca_key', args.ca_key)
        
        # Save updated config
        self.config.save_config()
    
    def format_size(self, size):
        """Format size in bytes to human-readable form"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"
    
    def format_duration(self, seconds):
        """Format duration in seconds to human-readable form"""
        m, s = divmod(int(seconds), 60)
        h, m = divmod(m, 60)
        d, h = divmod(h, 24)
        
        if d > 0:
            return f"{d}d {h}h {m}m {s}s"
        elif h > 0:
            return f"{h}h {m}m {s}s"
        elif m > 0:
            return f"{m}m {s}s"
        else:
            return f"{s}s"

def main():
    """Main entry point for CLI"""
    cli = CLI()
    args = cli.parse_arguments()
    
    if args.command == 'start':
        cli.start(args)
    elif args.command == 'stop':
        cli.stop()
    elif args.command == 'status':
        cli.status()
    elif args.command == 'generate-ca':
        cli.generate_ca(args)
    else:
        # Default to start if no command specified
        cli.start(args)

if __name__ == "__main__":
    main()
