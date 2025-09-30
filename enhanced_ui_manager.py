"""
Enhanced UI Manager for real-time fuzzing visualization.
Provides live updates, progress tracking, and modern terminal UI.
"""

import time
import threading
from typing import Any, Dict, Optional, Callable
from datetime import datetime
from queue import Queue, Empty

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, MofNCompleteColumn
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich import box
from rich.rule import Rule
from rich.status import Status


class LiveStats:
    """Container for live fuzzing statistics."""
    
    def __init__(self):
        self.executions = 0
        self.max_executions = 100000
        self.coverage_lines = 0
        self.crashes_found = 0
        self.executions_per_second = 0.0
        self.start_time = time.time()
        self.last_update = time.time()
        self.current_endpoint = "Initializing..."
        self.current_test_case = "None"
        self.mutation_strategy = "Initial"
        self.fitness_score = 0.0
        self.coverage_files = set()
        self.recent_findings = []
        
    def update_executions(self, count: int):
        """Update execution count and calculate rate."""
        current_time = time.time()
        if current_time > self.last_update:
            self.executions_per_second = count / (current_time - self.start_time)
        self.executions = count
        self.last_update = current_time
    
    def add_coverage(self, files: set):
        """Add new coverage files."""
        new_files = files - self.coverage_files
        if new_files:
            self.coverage_lines += len(new_files)
            self.coverage_files.update(new_files)
    
    def add_crash(self, crash_info: Dict):
        """Add a new crash."""
        self.crashes_found += 1
        self.recent_findings.append({
            "type": "crash",
            "severity": crash_info.get("severity", "unknown"),
            "endpoint": crash_info.get("endpoint", "unknown"),
            "timestamp": datetime.now().strftime("%H:%M:%S")
        })
        # Keep only last 10 findings
        if len(self.recent_findings) > 10:
            self.recent_findings = self.recent_findings[-10:]


class EnhancedUIManager:
    """Enhanced UI manager with real-time updates and modern visualization."""
    
    def __init__(self, console: Console = None):
        self.console = console or Console(force_terminal=True, legacy_windows=False)
        self.stats = LiveStats()
        self.is_running = False
        self.update_queue = Queue()
        self.layout = None
        self.live = None
        
    def start_live_ui(self, plugin_name: str, max_executions: int = 100000):
        """Start the live updating UI."""
        self.stats.max_executions = max_executions
        self.stats.current_endpoint = plugin_name
        
        # Create layout
        self.layout = self._create_layout()
        
        # Start live display
        self.is_running = True
        
        with Live(self.layout, console=self.console, refresh_per_second=8, screen=True) as live:
            self.live = live
            
            # Show initial state
            self._update_display()
            
            try:
                while self.is_running:
                    # Process updates from queue
                    try:
                        while True:
                            update_type, data = self.update_queue.get_nowait()
                            self._process_update(update_type, data)
                    except Empty:
                        pass
                    
                    # Update display
                    self._update_display()
                    
                    # Small delay for smooth updates
                    time.sleep(0.125)  # 8 FPS
                    
            except KeyboardInterrupt:
                self.is_running = False
    
    def stop_live_ui(self):
        """Stop the live UI."""
        self.is_running = False
    
    def update_executions(self, count: int):
        """Update execution count."""
        self.update_queue.put(("executions", count))
    
    def update_coverage(self, files: set):
        """Update coverage information."""
        self.update_queue.put(("coverage", files))
    
    def update_crash(self, crash_info: Dict):
        """Update crash information."""
        self.update_queue.put(("crash", crash_info))
    
    def update_current_test(self, endpoint: str, test_case: str, strategy: str, fitness: float):
        """Update current test information."""
        self.update_queue.put(("current_test", {
            "endpoint": endpoint,
            "test_case": test_case,
            "strategy": strategy,
            "fitness": fitness
        }))
    
    def _process_update(self, update_type: str, data: Any):
        """Process an update from the queue."""
        if update_type == "executions":
            self.stats.update_executions(data)
        elif update_type == "coverage":
            self.stats.add_coverage(data)
        elif update_type == "crash":
            self.stats.add_crash(data)
        elif update_type == "current_test":
            self.stats.current_endpoint = data["endpoint"]
            self.stats.current_test_case = data["test_case"]
            self.stats.mutation_strategy = data["strategy"]
            self.stats.fitness_score = data["fitness"]
    
    def _create_layout(self) -> Layout:
        """Create the main layout."""
        layout = Layout()
        
        layout.split_column(
            Layout(self._create_header(), size=3, name="header"),
            Layout(self._create_progress_section(), size=6, name="progress"),
            Layout(self._create_stats_section(), size=8, name="stats"),
            Layout(self._create_current_test_section(), size=6, name="current"),
            Layout(self._create_findings_section(), size=8, name="findings")
        )
        
        return layout
    
    def _create_header(self) -> Panel:
        """Create the header panel."""
        header_text = Text()
        header_text.append("wpgarlic", style="bold blue")
        header_text.append(" - Enhanced WordPress Plugin Fuzzer", style="cyan")
        
        return Panel(
            Align.center(header_text),
            border_style="blue",
            box=box.ROUNDED
        )
    
    def _create_progress_section(self) -> Panel:
        """Create the progress section."""
        progress_text = Text()
        
        # Main progress bar
        progress = self.stats.executions / self.stats.max_executions * 100
        progress_bar = self._create_progress_bar(progress, 50)
        
        progress_text.append("Main Progress:\n", style="bold")
        progress_text.append(f"{progress_bar} {progress:.1f}%\n", style="green")
        progress_text.append(f"Executions: {self.stats.executions:,} / {self.stats.max_executions:,}\n", style="cyan")
        progress_text.append(f"Rate: {self.stats.executions_per_second:.1f} exec/s\n", style="yellow")
        
        return Panel(progress_text, title="Progress", border_style="green", box=box.ROUNDED)
    
    def _create_stats_section(self) -> Panel:
        """Create the statistics section."""
        stats_table = Table(show_header=True, header_style="bold blue", box=box.ROUNDED)
        stats_table.add_column("Metric", style="cyan", width=20)
        stats_table.add_column("Value", style="green", width=15)
        stats_table.add_column("Status", style="yellow", width=10)
        
        # Execution stats
        elapsed = time.time() - self.stats.start_time
        stats_table.add_row("Executions", f"{self.stats.executions:,}", "Running")
        stats_table.add_row("Coverage Lines", f"{self.stats.coverage_lines:,}", "Growing")
        stats_table.add_row("Crashes Found", f"{self.stats.crashes_found:,}", "Monitoring")
        stats_table.add_row("Exec Rate", f"{self.stats.executions_per_second:.1f}/s", "Active")
        stats_table.add_row("Elapsed Time", f"{elapsed:.1f}s", "Running")
        
        return Panel(stats_table, title="Statistics", border_style="blue", box=box.ROUNDED)
    
    def _create_current_test_section(self) -> Panel:
        """Create the current test section."""
        current_text = Text()
        current_text.append("Current Test:\n", style="bold")
        current_text.append(f"Endpoint: {self.stats.current_endpoint}\n", style="cyan")
        current_text.append(f"Strategy: {self.stats.mutation_strategy}\n", style="yellow")
        current_text.append(f"Fitness: {self.stats.fitness_score:.3f}\n", style="green")
        
        return Panel(current_text, title="Current Test", border_style="yellow", box=box.ROUNDED)
    
    def _create_findings_section(self) -> Panel:
        """Create the recent findings section."""
        if not self.stats.recent_findings:
            content = Text("No findings yet...", style="dim")
        else:
            findings_table = Table(show_header=True, header_style="bold red", box=box.ROUNDED)
            findings_table.add_column("Time", style="dim", width=8)
            findings_table.add_column("Type", style="red", width=8)
            findings_table.add_column("Severity", style="yellow", width=10)
            findings_table.add_column("Endpoint", style="cyan", width=20)
            
            for finding in self.stats.recent_findings[-5:]:  # Show last 5
                findings_table.add_row(
                    finding["timestamp"],
                    finding["type"],
                    finding["severity"],
                    finding["endpoint"]
                )
            
            content = findings_table
        
        return Panel(content, title="Recent Findings", border_style="red", box=box.ROUNDED)
    
    def _create_progress_bar(self, percentage: float, width: int = 50) -> str:
        """Create a text-based progress bar."""
        filled = int(percentage / 100 * width)
        bar = "█" * filled + "░" * (width - filled)
        return f"[green]{bar}[/green]"
    
    def _update_display(self):
        """Update the display with current statistics."""
        if self.live and self.layout:
            # Update all sections
            self.layout["progress"].update(self._create_progress_section())
            self.layout["stats"].update(self._create_stats_section())
            self.layout["current"].update(self._create_current_test_section())
            self.layout["findings"].update(self._create_findings_section())
    
    def show_final_summary(self):
        """Show final summary when fuzzing completes."""
        if self.live:
            self.live.stop()
        
        # Create final summary
        summary_text = Text()
        summary_text.append("Fuzzing Session Complete!\n\n", style="bold green")
        summary_text.append(f"Total Executions: {self.stats.executions:,}\n", style="cyan")
        summary_text.append(f"Coverage Lines: {self.stats.coverage_lines:,}\n", style="blue")
        summary_text.append(f"Crashes Found: {self.stats.crashes_found:,}\n", style="red")
        summary_text.append(f"Average Rate: {self.stats.executions_per_second:.1f} exec/s\n", style="yellow")
        
        elapsed = time.time() - self.stats.start_time
        summary_text.append(f"Total Time: {elapsed:.1f}s\n", style="magenta")
        
        summary_panel = Panel(
            Align.center(summary_text),
            title="Final Summary",
            border_style="green",
            box=box.DOUBLE
        )
        
        self.console.print(summary_panel)


def create_enhanced_ui_manager() -> EnhancedUIManager:
    """Create an enhanced UI manager instance."""
    return EnhancedUIManager()


if __name__ == "__main__":
    # Demo the enhanced UI
    ui_manager = create_enhanced_ui_manager()
    
    # Simulate fuzzing
    ui_manager.start_live_ui("demo-plugin", 10000)
    
    # Simulate updates
    for i in range(100):
        ui_manager.update_executions(i * 100)
        ui_manager.update_coverage({f"file_{j}.php" for j in range(i)})
        if i % 10 == 0:
            ui_manager.update_crash({
                "severity": "medium",
                "endpoint": f"/test/endpoint/{i}"
            })
        
        ui_manager.update_current_test(
            f"/test/endpoint/{i}",
            f"test_case_{i}",
            "havoc",
            i / 100.0
        )
        
        time.sleep(0.1)
    
    ui_manager.show_final_summary()
