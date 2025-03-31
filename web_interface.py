#!/usr/bin/env python3
"""
Web interface for NaptProxy
"""
import os
import logging
import json
import base64
import time
from datetime import datetime
from urllib.parse import parse_qs
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, Response
from config import Config

logger = logging.getLogger("NaptProxy.WebInterface")

app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", os.urandom(24).hex())

# Global proxy server instance (set by start_web_interface)
proxy_server = None
config_manager = Config()

def start_web_interface(host, port, proxy_instance):
    """
    Start the web interface
    
    Args:
        host (str): Host to bind
        port (int): Port to bind
        proxy_instance: ProxyServer instance
    """
    global proxy_server
    proxy_server = proxy_instance
    
    logger.info(f"Starting web interface on {host}:{port}")
    app.run(host=host, port=port, debug=True)

# Set the global proxy_server for use with gunicorn
def set_proxy_server(proxy_instance):
    global proxy_server
    proxy_server = proxy_instance
    return app

@app.route('/')
def index():
    """Render the dashboard page"""
    return render_template('index.html')

@app.route('/logs')
def logs():
    """Render the logs page"""
    return render_template('logs.html')

@app.route('/settings')
def settings():
    """Render the settings page"""
    return render_template('settings.html')

# API endpoints for AJAX requests

@app.route('/api/status')
def get_status():
    """Get proxy server status"""
    if proxy_server:
        return jsonify(proxy_server.get_status())
    return jsonify({"error": "Proxy server not available"})

@app.route('/api/stats')
def get_stats():
    """Get traffic statistics"""
    if proxy_server and proxy_server.analyzer:
        return jsonify(proxy_server.analyzer.get_stats())
    return jsonify({"error": "Traffic analyzer not available"})

@app.route('/api/transactions')
def get_transactions():
    """Get transaction logs with optional filtering"""
    if not proxy_server or not proxy_server.analyzer:
        return jsonify({"error": "Traffic analyzer not available"})
    
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))
    filter_type = request.args.get('filter_type')
    filter_value = request.args.get('filter_value')
    
    transactions = proxy_server.analyzer.get_transactions(
        limit=limit, 
        offset=offset,
        filter_type=filter_type,
        filter_value=filter_value
    )
    
    return jsonify({
        "transactions": transactions,
        "total": len(proxy_server.analyzer.transactions)
    })

@app.route('/api/vulnerabilities')
def get_vulnerabilities():
    """Get vulnerability summary"""
    if proxy_server and proxy_server.analyzer:
        return jsonify(proxy_server.analyzer.get_vulnerability_summary())
    return jsonify({"error": "Traffic analyzer not available"})

@app.route('/api/config', methods=['GET'])
def get_config():
    """Get current configuration"""
    return jsonify(config_manager.config)

@app.route('/api/config', methods=['POST'])
def update_config():
    """Update configuration"""
    try:
        new_config = request.json
        config_manager.update(new_config)
        return jsonify({"success": True, "message": "Configuration updated"})
    except Exception as e:
        logger.error(f"Error updating configuration: {str(e)}")
        return jsonify({"error": str(e)})

@app.route('/api/transaction/<int:index>')
def get_transaction_detail(index):
    """Get detailed information for a specific transaction"""
    if not proxy_server or not proxy_server.analyzer:
        return jsonify({"error": "Traffic analyzer not available"})
    
    if index < 0 or index >= len(proxy_server.analyzer.transactions):
        return jsonify({"error": "Transaction index out of range"})
    
    transaction = proxy_server.analyzer.transactions[index]
    
    # Decode raw request and response for display
    if 'raw' in transaction['request']:
        try:
            transaction['request']['raw_decoded'] = base64.b64decode(
                transaction['request']['raw']).decode('utf-8', 'ignore')
        except:
            transaction['request']['raw_decoded'] = "Binary data"
    
    if 'raw' in transaction['response'] and transaction['response']['raw']:
        try:
            transaction['response']['raw_decoded'] = base64.b64decode(
                transaction['response']['raw']).decode('utf-8', 'ignore')
        except:
            transaction['response']['raw_decoded'] = "Binary data"
    
    return jsonify(transaction)

# Helper functions for templates
@app.template_filter('timestamp')
def format_timestamp(timestamp):
    """Format timestamp for display"""
    return datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

@app.template_filter('filesize')
def format_filesize(size):
    """Format file size for display"""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if size < 1024.0:
            return f"{size:.2f} {unit}"
        size /= 1024.0
    return f"{size:.2f} TB"
