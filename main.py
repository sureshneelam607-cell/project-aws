#!/usr/bin/env python3
"""
NaptProxy - A Python-based proxy server for intercepting and analyzing vulnerability scanner traffic
"""
import os
import sys
import logging
import threading
import argparse
from proxy_server import ProxyServer
from web_interface import app, start_web_interface, set_proxy_server

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("naptyproxy.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("NaptProxy")

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description='NaptProxy - A vulnerability scanner traffic proxy server')
    
    # Proxy configuration
    parser.add_argument('--proxy-host', type=str, default='0.0.0.0',
                        help='Host for the proxy server (default: 0.0.0.0)')
    parser.add_argument('--proxy-port', type=int, default=8000,
                        help='Port for the proxy server (default: 8000)')
    
    # Web interface configuration
    parser.add_argument('--web-host', type=str, default='0.0.0.0',
                        help='Host for the web interface (default: 0.0.0.0)')
    parser.add_argument('--web-port', type=int, default=5000,
                        help='Port for the web interface (default: 5000)')
    
    # Logging configuration
    parser.add_argument('--log-level', type=str, choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        default='INFO', help='Set the logging level (default: INFO)')
    parser.add_argument('--log-file', type=str, default='naptyproxy.log',
                        help='File to save logs (default: naptyproxy.log)')
    
    # SSL interception
    parser.add_argument('--intercept-ssl', action='store_true',
                        help='Enable SSL/TLS interception (requires CA certificate)')
    parser.add_argument('--ca-cert', type=str, default='ca/ca.crt',
                        help='Path to CA certificate (default: ca/ca.crt)')
    parser.add_argument('--ca-key', type=str, default='ca/ca.key',
                        help='Path to CA private key (default: ca/ca.key)')
    
    # Advanced options
    parser.add_argument('--buffer-size', type=int, default=8192,
                        help='Socket buffer size in bytes (default: 8192)')
    parser.add_argument('--timeout', type=int, default=60,
                        help='Socket timeout in seconds (default: 60)')
    parser.add_argument('--max-connections', type=int, default=100,
                        help='Maximum number of concurrent connections (default: 100)')
    
    return parser.parse_args()

# Create and configure proxy server with default settings
# This instance will be used when running with Gunicorn
default_proxy = ProxyServer(
    host='0.0.0.0',
    port=8000,
    buffer_size=8192,
    timeout=60,
    max_connections=100,
    intercept_ssl=False,
    ca_cert='ca/ca.crt',
    ca_key='ca/ca.key'
)

# Start the proxy server in a thread
proxy_thread = threading.Thread(target=default_proxy.start)
proxy_thread.daemon = True
proxy_thread.start()

# Set the proxy server instance in the Flask app and get the configured app
app = set_proxy_server(default_proxy)

if __name__ == "__main__":
    args = parse_arguments()
    
    # Set log level based on arguments
    log_level = getattr(logging, args.log_level)
    logging.basicConfig(level=log_level)
    
    # Create and configure proxy server with command line arguments
    proxy_server = ProxyServer(
        host=args.proxy_host,
        port=args.proxy_port,
        buffer_size=args.buffer_size,
        timeout=args.timeout,
        max_connections=args.max_connections,
        intercept_ssl=args.intercept_ssl,
        ca_cert=args.ca_cert,
        ca_key=args.ca_key
    )
    
    # Start proxy server in a separate thread
    proxy_thread = threading.Thread(target=proxy_server.start)
    proxy_thread.daemon = True
    proxy_thread.start()
    
    logger.info(f"Proxy server started on {args.proxy_host}:{args.proxy_port}")
    
    # Start web interface (this will block)
    start_web_interface(args.web_host, args.web_port, proxy_server)
