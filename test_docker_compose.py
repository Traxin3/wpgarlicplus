#!/usr/bin/env python3
"""
Test Docker Compose compatibility.
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fuzzer_container import _get_docker_compose_cmd
import subprocess

def test_docker_compose():
    print("Testing Docker Compose compatibility...")
    
    # Test the helper function
    docker_compose_cmd = _get_docker_compose_cmd()
    print(f"Docker Compose command: {' '.join(docker_compose_cmd)}")
    
    # Test if the command works
    try:
        result = subprocess.check_output(docker_compose_cmd + ["version"], stderr=subprocess.DEVNULL)
        print(f"✅ Docker Compose working: {result.decode().strip()}")
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"❌ Docker Compose failed: {e}")
        return False

def test_containers():
    print("\nTesting container status...")
    
    docker_compose_cmd = _get_docker_compose_cmd()
    
    try:
        # Test docker compose ps
        result = subprocess.check_output(docker_compose_cmd + ["ps"], stderr=subprocess.DEVNULL)
        print("✅ Container status:")
        print(result.decode())
        return True
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"❌ Failed to get container status: {e}")
        return False

if __name__ == "__main__":
    compose_ok = test_docker_compose()
    if compose_ok:
        test_containers()
    else:
        print("\n🔧 To fix Docker Compose issues:")
        print("1. Install Docker Compose: sudo apt install docker-compose")
        print("2. Or install Docker Compose v2: sudo apt install docker-compose-plugin")
        print("3. Start containers: docker-compose up -d")
