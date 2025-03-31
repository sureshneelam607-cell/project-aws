#!/usr/bin/env python3
"""
Configuration management for NaptProxy
"""
import os
import json
import logging

logger = logging.getLogger("NaptProxy.Config")

class Config:
    def __init__(self, config_file='config.json'):
        """
        Initialize configuration
        
        Args:
            config_file (str): Path to the configuration file
        """
        self.config_file = config_file
        self.default_config = {
            'proxy': {
                'host': '0.0.0.0',
                'port': 8000,
                'buffer_size': 8192,
                'timeout': 60,
                'max_connections': 100
            },
            'web_interface': {
                'host': '0.0.0.0',
                'port': 5000,
                'enable': True
            },
            'ssl': {
                'intercept': False,
                'ca_cert': 'ca/ca.crt',
                'ca_key': 'ca/ca.key'
            },
            'logging': {
                'level': 'INFO',
                'file': 'naptyproxy.log',
                'max_log_entries': 1000
            },
            'filters': {
                'ignored_hosts': [],
                'ignored_extensions': ['.css', '.js', '.jpg', '.png', '.gif', '.ico', '.svg'],
                'ignored_content_types': ['image/', 'font/', 'application/javascript']
            }
        }
        
        self.config = self.load_config()
    
    def load_config(self):
        """
        Load configuration from file or create default
        
        Returns:
            dict: Configuration dictionary
        """
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    logger.info(f"Loaded configuration from {self.config_file}")
                    
                    # Merge with default config for any missing fields
                    merged_config = self.default_config.copy()
                    self.deep_update(merged_config, config)
                    return merged_config
            else:
                self.save_config(self.default_config)
                logger.info(f"Created default configuration at {self.config_file}")
                return self.default_config
        except Exception as e:
            logger.error(f"Error loading configuration: {str(e)}")
            return self.default_config
    
    def save_config(self, config=None):
        """
        Save configuration to file
        
        Args:
            config (dict): Configuration to save, or None to save current config
        """
        try:
            if config is None:
                config = self.config
                
            with open(self.config_file, 'w') as f:
                json.dump(config, f, indent=4)
                logger.info(f"Saved configuration to {self.config_file}")
        except Exception as e:
            logger.error(f"Error saving configuration: {str(e)}")
    
    def get(self, section, key=None, default=None):
        """
        Get configuration value
        
        Args:
            section (str): Configuration section
            key (str): Configuration key, or None to get entire section
            default: Default value if section/key doesn't exist
            
        Returns:
            Configuration value or default
        """
        if section not in self.config:
            return default
            
        if key is None:
            return self.config[section]
            
        return self.config[section].get(key, default)
    
    def set(self, section, key, value):
        """
        Set configuration value
        
        Args:
            section (str): Configuration section
            key (str): Configuration key
            value: Value to set
        """
        if section not in self.config:
            self.config[section] = {}
            
        self.config[section][key] = value
    
    def update(self, new_config):
        """
        Update configuration with new values
        
        Args:
            new_config (dict): New configuration dictionary
        """
        self.deep_update(self.config, new_config)
        self.save_config()
    
    def deep_update(self, target, source):
        """
        Recursively update nested dictionaries
        
        Args:
            target (dict): Target dictionary to update
            source (dict): Source dictionary with new values
        """
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self.deep_update(target[key], value)
            else:
                target[key] = value
