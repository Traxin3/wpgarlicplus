#!/usr/bin/env python3
"""
Simple test for smart setup functionality without emojis.
"""

import sys
import os
from pathlib import Path

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def test_setup_state():
    """Test the setup state management."""
    print("Testing SetupState...")
    
    try:
        from setup_manager import SetupState
        
        # Create a test state
        state = SetupState(".test_wpgarlic_state")
        
        # Test first run detection
        is_first = state.is_first_run()
        print(f"First run: {is_first}")
        
        # Test plugin caching
        plugin_cached = state.is_plugin_cached("test-plugin", "1.0.0")
        print(f"Plugin cached: {plugin_cached}")
        
        # Test caching a plugin
        setup_data = {"test": "data", "plugin": "test-plugin"}
        state.cache_plugin_setup("test-plugin", "1.0.0", setup_data)
        
        # Test retrieving cache
        cached_data = state.get_plugin_cache("test-plugin", "1.0.0")
        print(f"Cached data: {cached_data}")
        
        # Test adding setup history
        state.add_setup_history("test-plugin", "1.0.0", 45.2, True)
        
        # Clean up test state
        import shutil
        if Path(".test_wpgarlic_state").exists():
            shutil.rmtree(".test_wpgarlic_state")
        
        print("SetupState tests passed!")
        return True
        
    except Exception as e:
        print(f"SetupState test failed: {e}")
        return False


def test_smart_setup_manager():
    """Test the smart setup manager."""
    print("Testing SmartSetupManager...")
    
    try:
        from setup_manager import SmartSetupManager
        
        # Create manager
        manager = SmartSetupManager()
        
        # Test stats
        stats = manager.get_setup_stats()
        print(f"Setup stats: {stats}")
        
        print("SmartSetupManager tests passed!")
        return True
        
    except Exception as e:
        print(f"SmartSetupManager test failed: {e}")
        return False


def test_integration():
    """Test integration with enhanced fuzzer."""
    print("Testing integration...")
    
    try:
        # Test that we can import the enhanced fuzzer with setup manager
        from enhanced_fuzzer import EnhancedFuzzer
        from fuzzing_config import create_default_config, FuzzingMode
        
        config = create_default_config(FuzzingMode.BALANCED)
        fuzzer = EnhancedFuzzer(config)
        
        print("Integration tests passed!")
        return True
        
    except Exception as e:
        print(f"Integration test failed: {e}")
        return False


def main():
    """Run all tests."""
    print("=" * 50)
    print("Smart Setup Manager Tests")
    print("=" * 50)
    
    tests = [
        ("SetupState", test_setup_state),
        ("SmartSetupManager", test_smart_setup_manager),
        ("Integration", test_integration)
    ]
    
    passed = 0
    total = len(tests)
    
    for test_name, test_func in tests:
        print(f"\nRunning {test_name} tests...")
        if test_func():
            passed += 1
            print(f"{test_name} tests: PASSED")
        else:
            print(f"{test_name} tests: FAILED")
    
    print("\n" + "=" * 50)
    print(f"Test Results: {passed}/{total} test suites passed")
    print("=" * 50)
    
    if passed == total:
        print("All tests passed! Smart setup is ready to use.")
        return 0
    else:
        print("Some tests failed. Please check the errors above.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
