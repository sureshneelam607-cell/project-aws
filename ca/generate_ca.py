#!/usr/bin/env python3
"""
CA certificate generation for NaptProxy
"""
import os
import logging
import OpenSSL.crypto as crypto
import datetime

logger = logging.getLogger("NaptProxy.CA")

def generate_ca_certificate(ca_name="NaptProxy CA", ca_dir="ca"):
    """
    Generate a CA certificate and private key
    
    Args:
        ca_name (str): Name of the CA
        ca_dir (str): Directory to save the CA certificate and key
        
    Returns:
        tuple: (certificate path, private key path)
    """
    # Create CA directory if it doesn't exist
    if not os.path.exists(ca_dir):
        os.makedirs(ca_dir)
    
    cert_path = os.path.join(ca_dir, "ca.crt")
    key_path = os.path.join(ca_dir, "ca.key")
    
    # Check if certificate and key already exist
    if os.path.exists(cert_path) and os.path.exists(key_path):
        logger.info(f"CA certificate and key already exist at {cert_path} and {key_path}")
        return cert_path, key_path
    
    # Generate a new private key
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 4096)
    
    # Create a self-signed CA certificate
    cert = crypto.X509()
    cert.set_version(2)  # X509v3
    
    # Set serial number
    cert.set_serial_number(int(datetime.datetime.now().timestamp() * 1000))
    
    # Set subject
    subj = cert.get_subject()
    subj.CN = ca_name
    subj.O = "NaptProxy"
    subj.OU = "Security"
    subj.C = "US"
    
    # Set validity period (10 years)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)
    
    # Set issuer (same as subject for self-signed)
    cert.set_issuer(cert.get_subject())
    
    # Set public key
    cert.set_pubkey(key)
    
    # Add X509v3 extensions
    extensions = [
        crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE, pathlen:0'),
        crypto.X509Extension(b'keyUsage', True, b'keyCertSign, cRLSign'),
        crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=cert)
    ]
    
    for ext in extensions:
        cert.add_extensions([ext])
    
    # Add Authority Key Identifier
    auth_key_id = crypto.X509Extension(b'authorityKeyIdentifier', False, b'keyid:always', issuer=cert)
    cert.add_extensions([auth_key_id])
    
    # Sign the certificate with the private key
    cert.sign(key, 'sha256')
    
    # Save the certificate
    with open(cert_path, 'wb') as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
    
    # Save the private key
    with open(key_path, 'wb') as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
    
    logger.info(f"Generated CA certificate and key at {cert_path} and {key_path}")
    
    return cert_path, key_path
