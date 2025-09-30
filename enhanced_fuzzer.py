"""
Enhanced fuzzing orchestrator that integrates feedback-guided fuzzing,
coverage tracking, and Rich console UI for WordPress plugin fuzzing.
"""

import json
import os
import random
import signal
import sys
import threading
import time
import traceback
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from feedback_engine import FeedbackEngine, TestCase, CoverageInfo
from rich_console import FuzzingConsole
from coverage_tracker import CoverageTracker
from fuzzing_config import (
    FuzzingConfiguration, ConfigurationManager, FuzzingMode,
    create_default_config, load_config_file
)
from fuzz_object import fuzz_object, ObjectType
from fuzzer_container import (
    reinitialize_containers, install_plugin_from_slug, activate_plugin,
    patch_wordpress, patch_plugins_themes, get_container_id,
    disconnect_network, disconnect_dns, visit_admin_homepage,
    fuzz_actions, fuzz_actions_admin, fuzz_rest_routes, fuzz_menu,
    fuzz_pages, fuzz_shortcodes, find_payloads_in_files,
    find_payloads_in_pages, find_payloads_in_admin
)
from setup_manager import SmartSetupManager, run_smart_setup
from enhanced_ui_manager import EnhancedUIManager
import crash_detector
import filtering


class EnhancedFuzzer:
    """Enhanced fuzzing orchestrator with feedback-guided capabilities."""
    
    def __init__(self, config: FuzzingConfiguration = None):
        self.config = config or create_default_config()
        # Configure console for Windows compatibility
        self.console = Console(force_terminal=True, legacy_windows=False)
        self.fuzzing_console = None
        self.feedback_engine = None
        self.coverage_tracker = None
        
        # State management
        self.is_running = False
        self.should_stop = False
        self.current_plugin = None
        self.current_endpoint = None
        
        # Statistics
        self.start_time = time.time()
        self.total_executions = 0
        self.crashes_found = 0
        self.coverage_growth = 0
        
        # Signal handling
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Initialize components
        self._initialize_components()
    
    def _signal_handler(self, signum, frame):
        """Handle shutdown signals."""
        self.console.print("\n[yellow]Received shutdown signal, stopping fuzzer...[/yellow]")
        self.should_stop = True
    
    def _initialize_components(self):
        """Initialize all fuzzing components."""
        # Initialize feedback engine
        self.feedback_engine = FeedbackEngine(self.console, self.config.__dict__)
        
        # Initialize coverage tracker
        if self.config.coverage.enable_coverage:
            plugin_path = f"/var/www/html/wp-content/plugins/{self.config.wordpress.target_slug}"
            self.coverage_tracker = CoverageTracker(
                plugin_path=plugin_path,
                output_dir=os.path.join(self.config.output.output_directory, "coverage")
            )
        
        # Initialize Rich console and enhanced UI
        self.fuzzing_console = FuzzingConsole(self.feedback_engine)
        self.ui_manager = EnhancedUIManager()
        
        self.console.print("[green]Enhanced fuzzing components initialized[/green]")
    
    def setup_wordpress_environment(self, plugin_slug: str, version: str = None):
        """Setup WordPress environment using smart setup manager."""
        self.fuzzing_console.print_info(f"Starting smart setup for plugin: {plugin_slug}")
        
        try:
            # Use smart setup manager
            setup_manager = SmartSetupManager()
            
            # Run smart setup process
            success = run_smart_setup(plugin_slug, version)
            
            if not success:
                raise Exception("Smart setup failed")
            
            # Additional setup for fuzzing-specific components
            self.fuzzing_console.print_status("Initializing fuzzing components...", "blue")
            
            # Visit admin homepage to trigger initialization
            for i in range(3):
                visit_admin_homepage()
            
            self.current_plugin = plugin_slug
            self.fuzzing_console.print_success(f"WordPress environment ready for {plugin_slug}")
            
        except Exception as e:
            self.fuzzing_console.print_error(f"Failed to setup WordPress environment: {e}")
            raise
    
    def execute_test_case(self, test_case: TestCase) -> Dict[str, Any]:
        """Execute a single test case and return results."""
        start_time = time.time()
        
        try:
            # Generate payload based on test case
            payload = test_case.payload
            
            # Execute fuzzing based on configuration
            results = []
            
            if self.config.wordpress.fuzz_ajax_actions:
                results.extend(self._fuzz_ajax_actions(payload))
            
            if self.config.wordpress.fuzz_rest_endpoints:
                results.extend(self._fuzz_rest_endpoints(payload))
            
            if self.config.wordpress.fuzz_admin_pages:
                results.extend(self._fuzz_admin_pages(payload))
            
            if self.config.wordpress.fuzz_shortcodes:
                results.extend(self._fuzz_shortcodes(payload))
            
            # Combine results
            combined_output = ""
            combined_stdout = ""
            combined_stderr = ""
            
            for result in results:
                combined_output += result.get("output", "")
                combined_stdout += result.get("stdout", "")
                combined_stderr += result.get("stderr", "")
            
            execution_time = time.time() - start_time
            
            # Create coverage info
            coverage = CoverageInfo(
                execution_time=execution_time,
                memory_usage=self.coverage_tracker.get_memory_usage() if self.coverage_tracker else 0
            )
            
            # Parse coverage from output
            if self.coverage_tracker:
                self.coverage_tracker.record_execution(combined_output, execution_time)
                coverage.coverage_map = self.coverage_tracker.file_coverage
                coverage.total_coverage = self.coverage_tracker.total_executions
                coverage.unique_paths = self.coverage_tracker.path_coverage
            
            # Update test case with results
            test_case.coverage = coverage
            test_case.execution_count += 1
            test_case.last_executed = time.time()
            
            # Check for crashes
            crash_info = None
            if self.config.crash.enable_crash_detection:
                crash_info = self._analyze_output_for_crashes(combined_output)
                if crash_info:
                    test_case.crash_info = crash_info
                    self.crashes_found += 1
            
            return {
                "success": True,
                "output": combined_output,
                "stdout": combined_stdout,
                "stderr": combined_stderr,
                "execution_time": execution_time,
                "coverage": coverage,
                "crash_info": crash_info
            }
            
        except Exception as e:
            execution_time = time.time() - start_time
            return {
                "success": False,
                "error": str(e),
                "execution_time": execution_time,
                "traceback": traceback.format_exc()
            }
    
    def _fuzz_ajax_actions(self, payload: Any) -> List[Dict[str, Any]]:
        """Fuzz AJAX actions with the given payload."""
        results = []
        
        try:
            # Fuzz non-admin actions
            results.extend(fuzz_actions("RANDOM", "ALL", self.current_plugin))
            
            # Fuzz admin actions
            results.extend(fuzz_actions_admin("RANDOM", "ALL", self.current_plugin))
            
        except Exception as e:
            results.append({
                "output": "",
                "stdout": "",
                "stderr": f"AJAX fuzzing error: {e}",
                "return_code": 1
            })
        
        return results
    
    def _fuzz_rest_endpoints(self, payload: Any) -> List[Dict[str, Any]]:
        """Fuzz REST endpoints with the given payload."""
        results = []
        
        try:
            results.extend(fuzz_rest_routes("RANDOM", "ALL", self.current_plugin))
        except Exception as e:
            results.append({
                "output": "",
                "stdout": "",
                "stderr": f"REST fuzzing error: {e}",
                "return_code": 1
            })
        
        return results
    
    def _fuzz_admin_pages(self, payload: Any) -> List[Dict[str, Any]]:
        """Fuzz admin pages with the given payload."""
        results = []
        
        try:
            # Fuzz menu pages for different user roles
            for role_id in [1, 2]:  # admin, subscriber
                results.extend(fuzz_menu("RANDOM", "ALL", self.current_plugin, role_id))
            
            # Fuzz regular pages
            results.extend(fuzz_pages("RANDOM", 0))  # Not logged in
            results.extend(fuzz_pages("RANDOM", 2))  # Subscriber
            
        except Exception as e:
            results.append({
                "output": "",
                "stdout": "",
                "stderr": f"Admin page fuzzing error: {e}",
                "return_code": 1
            })
        
        return results
    
    def _fuzz_shortcodes(self, payload: Any) -> List[Dict[str, Any]]:
        """Fuzz shortcodes with the given payload."""
        results = []
        
        try:
            results.extend(fuzz_shortcodes("RANDOM", "ALL", self.current_plugin))
        except Exception as e:
            results.append({
                "output": "",
                "stdout": "",
                "stderr": f"Shortcode fuzzing error: {e}",
                "return_code": 1
            })
        
        return results
    
    def _analyze_output_for_crashes(self, output: str) -> Optional[Dict[str, Any]]:
        """Analyze output for crash patterns."""
        # Use existing crash detection
        matchers = crash_detector.get_matchers(False)
        
        for matcher in matchers:
            match = matcher.search(output)
            if match:
                # Determine crash severity and type
                severity = "medium"
                crash_type = "unknown"
                
                if "fatal error" in output.lower():
                    severity = "high"
                    crash_type = "fatal_error"
                elif "sql syntax" in output.lower():
                    severity = "medium"
                    crash_type = "sql_injection"
                elif "<script>" in output.lower():
                    severity = "medium"
                    crash_type = "xss"
                
                return {
                    "severity": severity,
                    "type": crash_type,
                    "output": output,
                    "timestamp": time.time(),
                    "pattern": match.group(0)
                }
        
        return None
    
    def generate_initial_test_cases(self) -> List[TestCase]:
        """Generate initial test cases for fuzzing."""
        initial_test_cases = []
        
        # Load existing payloads from magic_payloads.php
        try:
            with open("docker_image/magic_payloads.php", "r") as f:
                content = f.read()
                import re
                payloads = re.findall(r'"([^"]*GARLIC[^"]*)"', content)
                
                for payload in payloads:
                    coverage = CoverageInfo()
                    test_case = TestCase(payload=payload, coverage=coverage)
                    initial_test_cases.append(test_case)
                    
        except FileNotFoundError:
            # Fallback to default payloads
            default_payloads = [
                "legitimateGARLIC",
                "</GARLIC'\"`>",
                "GARLIC GARLIC'\"`",
                "GARLIC GARLIC\\",
                "false",
                "0",
                "1",
                "http://GARLICGARLICGARLIC.example.com",
                'O:21:"GARLICNonexistentClass":0:{}',
                "legitimate.emailGARLIC@example.com"
            ]
            
            for payload in default_payloads:
                coverage = CoverageInfo()
                test_case = TestCase(payload=payload, coverage=coverage)
                initial_test_cases.append(test_case)
        
        return initial_test_cases
    
    def run_fuzzing_session(self, plugin_slug: str, version: str = None):
        """Run a complete fuzzing session."""
        try:
            # Setup environment
            self.setup_wordpress_environment(plugin_slug, version)
            
            # Generate initial test cases
            initial_test_cases = self.generate_initial_test_cases()
            
            # Add initial test cases to feedback engine
            for test_case in initial_test_cases:
                self.feedback_engine.add_test_case(
                    test_case.payload,
                    test_case.coverage,
                    mutation_strategy=None
                )
            
            self.console.print(f"[green]Added {len(initial_test_cases)} initial test cases[/green]")
            
            # Start enhanced UI in a separate thread
            ui_thread = threading.Thread(
                target=self.ui_manager.start_live_ui,
                args=(plugin_slug, self.config.performance.max_executions),
                daemon=True
            )
            ui_thread.start()
            
            # Give UI time to start
            time.sleep(1)
            
            # Start the fuzzing loop
            self.is_running = True
            self._fuzzing_loop()
            
            # Stop UI
            self.ui_manager.stop_live_ui()
            
        except Exception as e:
            self.console.print(f"[red]Fuzzing session failed: {e}[/red]")
            self.console.print(f"[dim]{traceback.format_exc()}[/dim]")
        finally:
            self._cleanup_session()
    
    def _fuzzing_loop(self):
        """Main fuzzing loop with enhanced UI updates."""
        last_stats_update = time.time()
        last_ui_update = time.time()
        
        while (not self.should_stop and 
               self.total_executions < self.config.performance.max_executions and
               len(self.feedback_engine.test_cases) < self.config.performance.max_test_cases):
            
            # Get next test case
            test_case = self.feedback_engine.get_next_test_case()
            if not test_case:
                # Generate new test cases through mutation
                self._generate_mutations()
                test_case = self.feedback_engine.get_next_test_case()
                if not test_case:
                    break
            
            # Execute test case
            result = self.execute_test_case(test_case)
            self.total_executions += 1
            
            # Update statistics
            if result["success"]:
                # Update feedback engine with results
                if result.get("coverage"):
                    self.feedback_engine._update_coverage_map(result["coverage"])
                
                # Check for new coverage
                if self.coverage_tracker:
                    new_coverage = self.coverage_tracker.get_new_coverage(set())
                    if new_coverage:
                        self.coverage_growth += len(new_coverage)
                        # Update UI with new coverage
                        self.ui_manager.update_coverage(new_coverage)
            
            # Check for crashes
            if result.get("crash"):
                self.ui_manager.update_crash(result["crash"])
            
            # Update UI with current test information
            current_time = time.time()
            if current_time - last_ui_update >= 0.1:  # Update UI every 100ms
                endpoint = result.get("endpoint", "Unknown")
                strategy = getattr(test_case, 'mutation_strategy', 'Initial')
                fitness = getattr(test_case, 'fitness_score', 0.0)
                
                self.ui_manager.update_current_test(
                    endpoint,
                    str(test_case)[:50] + "..." if len(str(test_case)) > 50 else str(test_case),
                    strategy,
                    fitness
                )
                
                # Update execution count
                self.ui_manager.update_executions(self.total_executions)
                
                last_ui_update = current_time
            
            # Update statistics periodically
            if current_time - last_stats_update >= self.config.performance.stats_update_interval:
                self.feedback_engine.update_stats()
                last_stats_update = current_time
            
            # Save checkpoint periodically
            if self.total_executions % self.config.checkpoint_interval == 0:
                self._save_checkpoint()
            
            # Small delay to prevent overwhelming the system
            time.sleep(0.01)
        
        # Show final report
        self.ui_manager.show_final_summary()
    
    def _generate_mutations(self):
        """Generate new test cases through mutation."""
        # Get a random test case to mutate
        if not self.feedback_engine.test_cases:
            return
        
        test_case_id = random.choice(list(self.feedback_engine.test_cases.keys()))
        test_case = self.feedback_engine.test_cases[test_case_id]
        
        # Generate mutations
        mutations = self.feedback_engine.mutate_test_case(test_case)
        
        # Add mutations to feedback engine
        for mutation in mutations[:5]:  # Limit mutations per generation
            self.feedback_engine.add_test_case(
                mutation.payload,
                mutation.coverage,
                parent_id=mutation.parent_id,
                mutation_strategy=mutation.mutation_path[-1] if mutation.mutation_path else None
            )
    
    def _save_checkpoint(self):
        """Save current fuzzing state."""
        checkpoint_file = os.path.join(
            self.config.output.output_directory,
            f"checkpoint_{int(time.time())}.json"
        )
        
        try:
            self.feedback_engine.save_state(checkpoint_file)
            self.console.print(f"[dim]Checkpoint saved: {checkpoint_file}[/dim]")
        except Exception as e:
            self.console.print(f"[yellow]Failed to save checkpoint: {e}[/yellow]")
    
    def _cleanup_session(self):
        """Cleanup after fuzzing session."""
        self.is_running = False
        
        # Save final reports
        if self.coverage_tracker:
            self.coverage_tracker.save_coverage_report()
        
        self.feedback_engine.save_state(
            os.path.join(self.config.output.output_directory, "final_state.json")
        )
        
        self.console.print("[green]Fuzzing session cleanup completed[/green]")


def main():
    """Main entry point for enhanced fuzzer."""
    console = Console()
    
    # Parse command line arguments
    import typer
    
    app = typer.Typer(help="Enhanced wpgarlic fuzzer with feedback-guided capabilities")
    
    @app.command()
    def fuzz(
        plugin_slug: str = typer.Argument(..., help="WordPress plugin slug to fuzz"),
        version: str = typer.Option(None, "--version", "-v", help="Plugin version to fuzz"),
        mode: str = typer.Option("balanced", "--mode", "-m", help="Fuzzing mode: fast, balanced, deep"),
        config_file: str = typer.Option(None, "--config", "-c", help="Configuration file path"),
        output_dir: str = typer.Option("fuzzing_results", "--output", "-o", help="Output directory")
    ):
        """Run enhanced fuzzing on a WordPress plugin."""
        
        # Load configuration
        if config_file and os.path.exists(config_file):
            config = load_config_file(config_file)
        else:
            try:
                fuzzing_mode = FuzzingMode(mode.lower())
                config = create_default_config(fuzzing_mode)
            except ValueError:
                console.print(f"[red]Invalid mode: {mode}. Valid modes: fast, balanced, deep[/red]")
                return
        
        # Override output directory if specified
        config.output.output_directory = output_dir
        config.wordpress.target_slug = plugin_slug
        if version:
            config.wordpress.target_version = version
        
        # Validate configuration
        manager = ConfigurationManager()
        manager.config = config  # Set the config before validation
        issues = manager.validate_config()
        if issues:
            console.print("[red]Configuration validation failed:[/red]")
            for issue in issues:
                console.print(f"  - {issue}")
            # Don't return, just warn and continue
            console.print("[yellow]Continuing with warnings...[/yellow]")
        
        # Create and run fuzzer
        fuzzer = EnhancedFuzzer(config)
        
        try:
            fuzzer.run_fuzzing_session(plugin_slug, version)
        except KeyboardInterrupt:
            console.print("\n[yellow]Fuzzing interrupted by user[/yellow]")
        except Exception as e:
            console.print(f"[red]Fuzzing failed: {e}[/red]")
    
    @app.command()
    def config(
        mode: str = typer.Argument(..., help="Fuzzing mode: fast, balanced, deep"),
        output_file: str = typer.Option("config.json", "--output", "-o", help="Output configuration file")
    ):
        """Generate a configuration file for the specified mode."""
        try:
            fuzzing_mode = FuzzingMode(mode.lower())
            config = create_default_config(fuzzing_mode)
            
            manager = ConfigurationManager()
            manager.save_config(output_file, config)
            
            console.print(f"[green]Configuration saved to {output_file}[/green]")
            
        except ValueError:
            console.print(f"[red]Invalid mode: {mode}. Valid modes: fast, balanced, deep[/red]")
    
    app()


if __name__ == "__main__":
    main()
