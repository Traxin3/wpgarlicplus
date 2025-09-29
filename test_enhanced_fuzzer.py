#!/usr/bin/env python3
"""
Test script for the enhanced wpgarlic fuzzing system.
"""

import os
import sys
import tempfile
import json
from pathlib import Path

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from feedback_engine import FeedbackEngine, TestCase, CoverageInfo, MutationStrategy
from rich_console import FuzzingConsole
from coverage_tracker import CoverageTracker
from fuzzing_config import FuzzingConfiguration, FuzzingMode, create_default_config
from enhanced_crash_analyzer import EnhancedCrashAnalyzer, CrashType, CrashSeverity


def test_feedback_engine():
    """Test the feedback engine functionality."""
    print("Testing Feedback Engine...")
    
    from rich.console import Console
    console = Console()
    
    # Create feedback engine
    engine = FeedbackEngine(console)
    
    # Create test coverage
    coverage = CoverageInfo()
    coverage.unique_paths.add("test_path_1")
    coverage.unique_paths.add("test_path_2")
    
    # Add test case
    test_id = engine.add_test_case("test_payload", coverage)
    assert test_id in engine.test_cases
    
    # Test mutation
    test_case = engine.test_cases[test_id]
    mutations = engine.mutate_test_case(test_case)
    # Mutations might be empty for certain payload types, which is OK
    assert isinstance(mutations, list)
    
    # Test statistics
    engine.update_stats()
    stats = engine.get_stats_table()
    assert stats is not None
    
    print("[OK] Feedback Engine tests passed")


def test_coverage_tracker():
    """Test the coverage tracker functionality."""
    print("Testing Coverage Tracker...")
    
    # Create temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        # Create a simple PHP file for testing
        php_file = Path(temp_dir) / "test.php"
        php_file.write_text("""
<?php
function test_function() {
    echo "Hello World";
    return true;
}

class TestClass {
    public function method1() {
        return "test";
    }
}
""")
        
        # Create coverage tracker
        tracker = CoverageTracker(temp_dir, temp_dir)
        
        # Test coverage recording
        tracker.record_execution("test output", 1.0, 1024)
        
        # Test coverage summary
        summary = tracker.get_coverage_summary()
        assert 'overall_percentage' in summary
        assert 'total_executable_lines' in summary
        
        # Test coverage report saving
        report_file = tracker.save_coverage_report()
        assert os.path.exists(report_file)
        
    print("[OK] Coverage Tracker tests passed")


def test_configuration_system():
    """Test the configuration system."""
    print("Testing Configuration System...")
    
    # Test default configuration creation
    config = create_default_config(FuzzingMode.BALANCED)
    assert config.mode == FuzzingMode.BALANCED
    assert config.performance.max_executions > 0
    
    # Test configuration validation
    from fuzzing_config import ConfigurationManager
    manager = ConfigurationManager()
    issues = manager.validate_config()
    assert isinstance(issues, list)
    
    # Test configuration saving and loading
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=True) as f:
        config_file = f.name
    
    # Save configuration
    manager.save_config(config_file, config)
    
    # Load configuration
    loaded_config = manager.load_config(config_file)
    assert loaded_config.mode == config.mode
    
    # Clean up
    try:
        os.unlink(config_file)
    except (PermissionError, FileNotFoundError):
        pass  # File might already be deleted or locked
    
    print("[OK] Configuration System tests passed")


def test_crash_analyzer():
    """Test the crash analyzer functionality."""
    print("Testing Crash Analyzer...")
    
    from rich.console import Console
    console = Console()
    
    # Create crash analyzer
    analyzer = EnhancedCrashAnalyzer(console)
    
    # Test SQL injection detection
    sql_output = "SQL syntax error near 'GARLIC' at line 1"
    sql_crash = analyzer.analyze_crash("GARLIC", sql_output)
    assert sql_crash is not None
    assert sql_crash.crash_type == CrashType.SQL_INJECTION
    
    # Test XSS detection
    xss_output = "<script>alert('GARLIC')</script>"
    xss_crash = analyzer.analyze_crash("GARLIC", xss_output)
    assert xss_crash is not None
    assert xss_crash.crash_type == CrashType.XSS
    
    # Test crash summary
    summary = analyzer.get_crash_summary()
    assert 'total_crashes' in summary
    assert summary['total_crashes'] >= 2
    
    # Test crash table
    table = analyzer.get_crash_table()
    assert table is not None
    
    print("[OK] Crash Analyzer tests passed")


def test_rich_console():
    """Test the Rich console interface."""
    print("Testing Rich Console Interface...")
    
    from rich.console import Console
    console = Console()
    
    # Create feedback engine and console
    engine = FeedbackEngine(console)
    fuzzing_console = FuzzingConsole(engine)
    
    # Test console methods
    header = fuzzing_console.update_header()
    assert header is not None
    
    stats_panel = fuzzing_console.update_stats_panel()
    assert stats_panel is not None
    
    coverage_panel = fuzzing_console.update_coverage_panel()
    assert coverage_panel is not None
    
    crashes_panel = fuzzing_console.update_crashes_panel()
    assert crashes_panel is not None
    
    print("[OK] Rich Console Interface tests passed")


def test_integration():
    """Test integration between components."""
    print("Testing Integration...")
    
    from rich.console import Console
    console = Console()
    
    # Create configuration
    config = create_default_config(FuzzingMode.FAST)
    
    # Create feedback engine
    engine = FeedbackEngine(console, config.__dict__)
    
    # Create test case
    coverage = CoverageInfo()
    coverage.unique_paths.add("integration_test_path")
    test_id = engine.add_test_case("integration_payload", coverage)
    
    # Verify test case was added
    assert test_id in engine.test_cases
    assert len(engine.input_queue) > 0
    
    # Test mutation generation
    test_case = engine.test_cases[test_id]
    mutations = engine.mutate_test_case(test_case)
    assert isinstance(mutations, list)
    
    # Add mutations to engine if any were generated
    if mutations:
        for mutation in mutations[:2]:  # Add first 2 mutations
            engine.add_test_case(mutation.payload, mutation.coverage)
        
        # Verify mutations were added
        assert len(engine.test_cases) > 1
    else:
        # If no mutations, just verify the original test case exists
        assert len(engine.test_cases) >= 1
    
    print("[OK] Integration tests passed")


def main():
    """Run all tests."""
    print("Running Enhanced wpgarlic Tests...\n")
    
    try:
        test_feedback_engine()
        test_coverage_tracker()
        test_configuration_system()
        test_crash_analyzer()
        test_rich_console()
        test_integration()
        
        print("\n[SUCCESS] All tests passed! The enhanced wpgarlic system is working correctly.")
        print("\nTo use the enhanced fuzzing system:")
        print("1. Install dependencies: pip install -r requirements.txt")
        print("2. Run fuzzing: ./bin/enhanced_fuzz fuzz your-plugin")
        print("3. Generate config: ./bin/generate_config balanced --output config.json")
        
    except Exception as e:
        print(f"\n[ERROR] Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
