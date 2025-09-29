#!/usr/bin/env python3
"""
Test script to debug the configuration issue.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fuzzing_config import FuzzingConfiguration, ConfigurationManager, FuzzingMode, create_default_config

def test_config():
    print("Testing configuration...")
    
    # Create a default config
    config = create_default_config(FuzzingMode.BALANCED)
    print(f"Default target_slug: '{config.wordpress.target_slug}'")
    
    # Set target_slug
    config.wordpress.target_slug = "page-builder-add"
    print(f"After setting target_slug: '{config.wordpress.target_slug}'")
    
    # Create manager and validate
    manager = ConfigurationManager()
    manager.config = config
    issues = manager.validate_config()
    
    print(f"Validation issues: {issues}")
    
    if not issues:
        print("✅ Configuration validation passed!")
    else:
        print("❌ Configuration validation failed!")

if __name__ == "__main__":
    test_config()
