#!/usr/bin/env python3
"""
Core proxy server implementation for NaptProxy
"""
import socket
import select
import threading
import logging
import time
import ssl
from urllib.parse import urlparse
import http.client
from https_intercept import HTTPSInterceptor
from traffic_analyzer import TrafficAnalyzer

logger = logging.getLogger("NaptProxy.ProxyServer")

class ProxyServer:
    def __init__(self, host='0.0.0.0', port=8000, buffer_size=8192, timeout=60,
                 max_connections=100, intercept_ssl=False, ca_cert=None, ca_key=None):
        """
        Initialize the proxy server
        
        Args:
            host (str): Host to bind the proxy server
            port (int): Port to bind the proxy server
            buffer_size (int): Socket buffer size in bytes
            timeout (int): Socket timeout in seconds
            max_connections (int): Maximum number of concurrent connections
            intercept_ssl (bool): Whether to intercept SSL/TLS traffic
            ca_cert (str): Path to CA certificate file
            ca_key (str): Path to CA private key file
        """
        self.host = host
        self.port = port
        self.buffer_size = buffer_size
        self.timeout = timeout
        self.max_connections = max_connections
        self.intercept_ssl = intercept_ssl
        self.running = False
        self.connections = []
        self.server_socket = None
        
        # Traffic analysis
        self.analyzer = TrafficAnalyzer()
        
        # HTTPS interception
        if intercept_ssl:
            if not ca_cert or not ca_key:
                logger.warning("SSL interception enabled but CA certificate or key not provided. SSL interception will be disabled.")
                self.intercept_ssl = False
            else:
                try:
                    self.https_interceptor = HTTPSInterceptor(ca_cert, ca_key)
                except Exception as e:
                    logger.error(f"Failed to initialize HTTPS interceptor: {str(e)}")
                    self.intercept_ssl = False
    
    def start(self):
        """Start the proxy server"""
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(self.max_connections)
        self.running = True
        
        logger.info(f"Proxy server started on {self.host}:{self.port}")
        logger.info(f"SSL interception: {'Enabled' if self.intercept_ssl else 'Disabled'}")
        
        try:
            while self.running:
                client_socket, client_address = self.server_socket.accept()
                client_socket.settimeout(self.timeout)
                
                # Start a new thread to handle this connection
                client_thread = threading.Thread(
                    target=self.handle_client_request,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
                
                # Keep track of connections for monitoring
                self.connections.append({
                    'client': client_address,
                    'start_time': time.time(),
                    'thread': client_thread
                })
                
                # Clean up finished connections
                self.connections = [conn for conn in self.connections if conn['thread'].is_alive()]
                
        except KeyboardInterrupt:
            logger.info("Proxy server stopping due to keyboard interrupt")
        except Exception as e:
            logger.error(f"Proxy server error: {str(e)}")
        finally:
            self.stop()
    
    def stop(self):
        """Stop the proxy server"""
        self.running = False
        if self.server_socket:
            self.server_socket.close()
        logger.info("Proxy server stopped")
    
    def handle_client_request(self, client_socket, client_address):
        """
        Handle client requests by parsing HTTP(S) headers and forwarding to server
        
        Args:
            client_socket (socket.socket): Client socket
            client_address (tuple): Client address (host, port)
        """
        try:
            # Receive initial request data
            initial_data = client_socket.recv(self.buffer_size)
            
            if not initial_data:
                client_socket.close()
                return
            
            # Log the request data for analysis
            self.analyzer.add_request(client_address, initial_data)
            
            # Check if it's a CONNECT request (for HTTPS)
            if initial_data.startswith(b'CONNECT'):
                self.handle_https_connect(client_socket, initial_data)
            else:
                self.handle_http_request(client_socket, initial_data)
            
        except Exception as e:
            logger.error(f"Error handling client request from {client_address}: {str(e)}")
        finally:
            try:
                client_socket.close()
            except:
                pass
    
    def handle_http_request(self, client_socket, request_data):
        """
        Handle HTTP requests
        
        Args:
            client_socket (socket.socket): Client socket
            request_data (bytes): Initial request data
        """
        # Parse the first line to get method, URL and version
        first_line = request_data.split(b'\n')[0].decode('utf-8', 'ignore')
        try:
            method, url, version = first_line.split(' ')
        except ValueError:
            logger.error(f"Invalid HTTP request: {first_line}")
            return
        
        # Parse URL to get host, port and path
        parsed_url = urlparse(url)
        host = parsed_url.netloc
        if ':' in host:
            host, port = host.split(':')
            port = int(port)
        else:
            port = 80
        
        path = parsed_url.path
        if parsed_url.query:
            path += '?' + parsed_url.query
        
        # Connect to the server
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(self.timeout)
            server_socket.connect((host, port))
            
            # Modify the request to use relative URL
            modified_request = request_data.replace(url.encode(), path.encode())
            
            # Send the request to the server
            server_socket.send(modified_request)
            
            # Forward data between client and server
            self.forward_data(client_socket, server_socket)
            
        except Exception as e:
            logger.error(f"Error forwarding HTTP request to {host}:{port}: {str(e)}")
        finally:
            try:
                server_socket.close()
            except:
                pass
    
    def handle_https_connect(self, client_socket, connect_data):
        """
        Handle HTTPS CONNECT requests
        
        Args:
            client_socket (socket.socket): Client socket
            connect_data (bytes): Initial CONNECT request data
        """
        # Parse the CONNECT request
        first_line = connect_data.split(b'\n')[0].decode('utf-8', 'ignore')
        try:
            method, target, version = first_line.split(' ')
        except ValueError:
            logger.error(f"Invalid CONNECT request: {first_line}")
            return
        
        # Parse target to get host and port
        host, port = target.split(':')
        port = int(port)
        
        # If SSL interception is disabled, just forward the traffic
        if not self.intercept_ssl:
            self.tunnel_https_connection(client_socket, host, port)
            return
        
        # If SSL interception is enabled
        try:
            # Send 200 Connection Established to the client
            client_socket.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            
            # Wrap the client socket with SSL/TLS
            ssl_client_socket = self.https_interceptor.wrap_client_socket(client_socket, host)
            
            # Connect to the server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(self.timeout)
            server_socket.connect((host, port))
            
            # Wrap the server socket with SSL/TLS
            ssl_context = ssl.create_default_context()
            ssl_server_socket = ssl_context.wrap_socket(server_socket, server_hostname=host)
            
            # Forward data between the SSL-wrapped sockets
            self.forward_data(ssl_client_socket, ssl_server_socket)
            
        except Exception as e:
            logger.error(f"Error intercepting HTTPS connection to {host}:{port}: {str(e)}")
        finally:
            try:
                ssl_client_socket.close()
                ssl_server_socket.close()
            except:
                pass
    
    def tunnel_https_connection(self, client_socket, host, port):
        """
        Tunnel an HTTPS connection without interception
        
        Args:
            client_socket (socket.socket): Client socket
            host (str): Target host
            port (int): Target port
        """
        try:
            # Send 200 Connection Established to the client
            client_socket.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            
            # Connect to the server
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.settimeout(self.timeout)
            server_socket.connect((host, port))
            
            # Forward data between client and server
            self.forward_data(client_socket, server_socket)
            
        except Exception as e:
            logger.error(f"Error tunneling HTTPS connection to {host}:{port}: {str(e)}")
        finally:
            try:
                server_socket.close()
            except:
                pass
    
    def forward_data(self, client_socket, server_socket):
        """
        Forward data between client and server sockets
        
        Args:
            client_socket (socket.socket): Client socket
            server_socket (socket.socket): Server socket
        """
        client_buffer = b''
        server_buffer = b''
        client_closed = False
        server_closed = False
        
        while not client_closed and not server_closed:
            # Wait for data from either socket
            inputs = []
            if not client_closed:
                inputs.append(client_socket)
            if not server_closed:
                inputs.append(server_socket)
                
            try:
                readable, _, exceptional = select.select(inputs, [], inputs, self.timeout)
            except select.error:
                break
            
            # Handle exceptional conditions
            for sock in exceptional:
                if sock is client_socket:
                    client_closed = True
                else:
                    server_closed = True
            
            # Handle readable sockets
            for sock in readable:
                if sock is client_socket:
                    try:
                        data = client_socket.recv(self.buffer_size)
                        if data:
                            server_socket.send(data)
                            client_buffer += data
                            # Analyze request data
                            self.analyzer.add_request_data(data)
                        else:
                            client_closed = True
                    except:
                        client_closed = True
                
                elif sock is server_socket:
                    try:
                        data = server_socket.recv(self.buffer_size)
                        if data:
                            client_socket.send(data)
                            server_buffer += data
                            # Analyze response data
                            self.analyzer.add_response_data(data)
                        else:
                            server_closed = True
                    except:
                        server_closed = True
        
        # Complete the traffic analysis
        self.analyzer.complete_transaction(client_buffer, server_buffer)
    
    def get_status(self):
        """Get the current status of the proxy server"""
        return {
            'running': self.running,
            'host': self.host,
            'port': self.port,
            'intercept_ssl': self.intercept_ssl,
            'connections': len(self.connections),
            'max_connections': self.max_connections,
            'traffic_stats': self.analyzer.get_stats()
        }
