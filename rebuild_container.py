#!/usr/bin/env python3
"""
Script to rebuild the Docker container with all necessary files.
"""

import subprocess
import sys
import os
from pathlib import Path


def run_command(command, description):
    """Run a command and handle errors."""
    print(f"Running: {description}")
    print(f"Command: {' '.join(command)}")
    
    try:
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        print(f"✓ {description} completed successfully")
        if result.stdout:
            print(f"Output: {result.stdout}")
        return True
    except subprocess.CalledProcessError as e:
        print(f"✗ {description} failed")
        print(f"Error: {e.stderr}")
        return False


def main():
    """Main function to rebuild the container."""
    print("=" * 60)
    print("Docker Container Rebuild Script")
    print("=" * 60)
    
    # Check if we're in the right directory
    if not Path("docker-compose.yml").exists():
        print("Error: docker-compose.yml not found. Please run this script from the wpgarlic root directory.")
        sys.exit(1)
    
    # Stop existing containers
    print("\n1. Stopping existing containers...")
    if not run_command(["docker-compose", "down"], "Stop containers"):
        print("Warning: Failed to stop containers, continuing anyway...")
    
    # Remove existing containers and volumes
    print("\n2. Removing existing containers and volumes...")
    run_command(["docker-compose", "rm", "-f", "-v"], "Remove containers and volumes")
    
    # Build new containers
    print("\n3. Building new containers...")
    if not run_command(["docker-compose", "build"], "Build containers"):
        print("Error: Failed to build containers")
        sys.exit(1)
    
    # Start containers
    print("\n4. Starting containers...")
    if not run_command(["docker-compose", "up", "-d"], "Start containers"):
        print("Error: Failed to start containers")
        sys.exit(1)
    
    # Wait for containers to be ready
    print("\n5. Waiting for containers to be ready...")
    time.sleep(10)
    
    # Check container status
    print("\n6. Checking container status...")
    run_command(["docker-compose", "ps"], "Check container status")
    
    # Test if coverage file is available
    print("\n7. Testing coverage file availability...")
    test_command = [
        "docker-compose", "exec", "-T", "wordpress1", 
        "test", "-f", "/fuzzer/coverage_instrumentation.php"
    ]
    
    if run_command(test_command, "Test coverage file"):
        print("✓ Coverage file is available in container")
    else:
        print("✗ Coverage file is missing from container")
        print("The coverage_instrumentation.php file may not have been copied properly.")
    
    # Test wp-config.php syntax
    print("\n8. Testing wp-config.php syntax...")
    syntax_test = [
        "docker-compose", "exec", "-T", "wordpress1",
        "php", "-l", "/var/www/html/wp-config.php"
    ]
    
    if run_command(syntax_test, "Test wp-config.php syntax"):
        print("✓ wp-config.php syntax is valid")
    else:
        print("✗ wp-config.php has syntax errors")
        print("You may need to run the fix_wp_config.sh script inside the container.")
    
    print("\n" + "=" * 60)
    print("Container rebuild completed!")
    print("=" * 60)
    print("\nNext steps:")
    print("1. Test the fuzzer: python bin/enhanced_fuzz fuzz payjustnow-for-woocommerce --mode deep")
    print("2. If you see coverage errors, run: docker-compose exec wordpress1 /fuzzer/fix_wp_config.sh")


if __name__ == "__main__":
    import time
    main()
