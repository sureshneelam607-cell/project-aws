#!/usr/bin/env python3
"""
HTTPS traffic interception functionality for NaptProxy
"""
import os
import ssl
import socket
import logging
import tempfile
import OpenSSL.crypto as crypto
import datetime

logger = logging.getLogger("NaptProxy.HTTPSInterceptor")

class HTTPSInterceptor:
    def __init__(self, ca_cert_path, ca_key_path):
        """
        Initialize the HTTPS interceptor
        
        Args:
            ca_cert_path (str): Path to the CA certificate file
            ca_key_path (str): Path to the CA private key file
        """
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self.cert_cache = {}
        
        # Load CA certificate and private key
        try:
            with open(ca_cert_path, 'rb') as f:
                self.ca_cert = crypto.load_certificate(crypto.FILETYPE_PEM, f.read())
            
            with open(ca_key_path, 'rb') as f:
                self.ca_key = crypto.load_privatekey(crypto.FILETYPE_PEM, f.read())
                
            logger.info("Successfully loaded CA certificate and private key")
        except Exception as e:
            logger.error(f"Failed to load CA certificate or private key: {str(e)}")
            raise
    
    def create_signed_certificate(self, hostname):
        """
        Create a new certificate signed by the CA for the given hostname
        
        Args:
            hostname (str): The hostname for which to create a certificate
            
        Returns:
            tuple: (certificate path, private key path)
        """
        # Check if certificate already exists in cache
        if hostname in self.cert_cache:
            return self.cert_cache[hostname]
        
        try:
            # Create a new key pair
            key = crypto.PKey()
            key.generate_key(crypto.TYPE_RSA, 2048)
            
            # Create a certificate signing request (CSR)
            csr = crypto.X509Req()
            subj = csr.get_subject()
            subj.CN = hostname
            csr.set_pubkey(key)
            csr.sign(key, 'sha256')
            
            # Create a certificate
            cert = crypto.X509()
            cert.set_version(2)
            cert.set_subject(csr.get_subject())
            cert.set_serial_number(int(datetime.datetime.now().timestamp() * 1000))
            
            # Set certificate validity
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # Valid for 1 year
            
            # Set issuer (CA)
            cert.set_issuer(self.ca_cert.get_subject())
            cert.set_pubkey(csr.get_pubkey())
            
            # Add X509v3 extensions
            extensions = [
                crypto.X509Extension(b'basicConstraints', False, b'CA:FALSE'),
                crypto.X509Extension(b'keyUsage', False, b'digitalSignature,keyEncipherment'),
                crypto.X509Extension(b'extendedKeyUsage', False, b'serverAuth'),
                crypto.X509Extension(b'subjectAltName', False, f'DNS:{hostname}'.encode())
            ]
            
            cert.add_extensions(extensions)
            
            # Sign the certificate with the CA key
            cert.sign(self.ca_key, 'sha256')
            
            # Save certificate and key to temporary files
            cert_path = os.path.join(tempfile.gettempdir(), f'{hostname}.crt')
            key_path = os.path.join(tempfile.gettempdir(), f'{hostname}.key')
            
            with open(cert_path, 'wb') as f:
                f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
            
            with open(key_path, 'wb') as f:
                f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
            
            # Cache the certificate and key paths
            self.cert_cache[hostname] = (cert_path, key_path)
            
            logger.debug(f"Created signed certificate for {hostname}")
            return cert_path, key_path
            
        except Exception as e:
            logger.error(f"Failed to create signed certificate for {hostname}: {str(e)}")
            raise
    
    def wrap_client_socket(self, client_socket, hostname):
        """
        Wrap a client socket with SSL using a dynamically generated certificate
        
        Args:
            client_socket (socket.socket): Client socket to wrap
            hostname (str): Hostname for which to generate certificate
            
        Returns:
            ssl.SSLSocket: SSL-wrapped socket
        """
        try:
            # Create signed certificate for hostname
            cert_path, key_path = self.create_signed_certificate(hostname)
            
            # Create SSL context
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_path, key_path)
            
            # Wrap the socket
            ssl_socket = context.wrap_socket(client_socket, server_side=True)
            
            return ssl_socket
            
        except Exception as e:
            logger.error(f"Failed to wrap client socket: {str(e)}")
            raise
