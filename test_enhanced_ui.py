#!/usr/bin/env python3
"""
Test script for the enhanced UI manager.
"""

import time
import sys
import os

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from enhanced_ui_manager import EnhancedUIManager


def test_enhanced_ui():
    """Test the enhanced UI manager."""
    print("Testing Enhanced UI Manager...")
    
    # Create UI manager
    ui_manager = EnhancedUIManager()
    
    try:
        # Start live UI in a separate thread
        import threading
        
        ui_thread = threading.Thread(
            target=ui_manager.start_live_ui,
            args=("test-plugin", 1000),
            daemon=True
        )
        ui_thread.start()
        
        # Give UI time to start
        time.sleep(1)
        
        # Simulate fuzzing updates
        print("Simulating fuzzing updates...")
        
        for i in range(100):
            # Update executions
            ui_manager.update_executions(i * 10)
            
            # Update coverage
            if i % 5 == 0:
                ui_manager.update_coverage({f"file_{j}.php" for j in range(i, i + 5)})
            
            # Update current test
            ui_manager.update_current_test(
                f"/test/endpoint/{i}",
                f"test_case_{i}",
                "havoc" if i % 2 == 0 else "bit_flip",
                i / 100.0
            )
            
            # Simulate crashes occasionally
            if i % 15 == 0:
                ui_manager.update_crash({
                    "severity": "medium" if i % 30 == 0 else "low",
                    "endpoint": f"/test/endpoint/{i}"
                })
            
            time.sleep(0.1)
        
        # Stop UI
        ui_manager.stop_live_ui()
        
        # Show final summary
        ui_manager.show_final_summary()
        
        print("Enhanced UI test completed successfully!")
        return True
        
    except Exception as e:
        print(f"Enhanced UI test failed: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = test_enhanced_ui()
    sys.exit(0 if success else 1)
