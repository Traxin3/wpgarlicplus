"""
Rich-based console UI for wpgarlic fuzzing tool.
Provides real-time visualization of fuzzing progress, statistics, and results.
"""

import time
from typing import Any, Dict, List, Optional
from datetime import datetime, timedelta

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn
from rich.layout import Layout
from rich.live import Live
from rich.text import Text
from rich.align import Align
from rich.columns import Columns
from rich.status import Status
from rich.syntax import Syntax
from rich.tree import Tree
from rich import box

from feedback_engine import FeedbackEngine, FuzzingStats, TestCase, CrashSeverity


class FuzzingConsole:
    """Rich-based console interface for fuzzing operations."""
    
    def __init__(self, feedback_engine: FeedbackEngine):
        self.feedback_engine = feedback_engine
        self.console = Console()
        self.start_time = time.time()
        
        # UI state
        self.current_plugin = "Unknown"
        self.current_endpoint = "Unknown"
        self.last_update = time.time()
        self.update_interval = 1.0  # Update UI every second
        
        # Progress tracking
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),
            console=self.console
        )
        
        # Status tracking
        self.status = Status("Initializing fuzzer...")
        
    def start_fuzzing_session(self, plugin_name: str, endpoint: str = None):
        """Start a new fuzzing session."""
        self.current_plugin = plugin_name
        self.current_endpoint = endpoint or "All endpoints"
        self.start_time = time.time()
        
        self.console.clear()
        self.console.print(Panel.fit(
            f"[bold blue]wpgarlic[/bold blue] - Feedback-Guided WordPress Plugin Fuzzer\n"
            f"[green]Plugin:[/green] {plugin_name}\n"
            f"[green]Endpoint:[/green] {self.current_endpoint}\n"
            f"[green]Started:[/green] {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            title="Fuzzing Session",
            border_style="blue"
        ))
        
    def create_layout(self) -> Layout:
        """Create the main layout for the fuzzing interface."""
        layout = Layout()
        
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        
        layout["main"].split_row(
            Layout(name="left"),
            Layout(name="right")
        )
        
        layout["left"].split_column(
            Layout(name="stats", size=10),
            Layout(name="coverage", size=8),
            Layout(name="crashes")
        )
        
        layout["right"].split_column(
            Layout(name="progress", size=6),
            Layout(name="current_test", size=8),
            Layout(name="recent_findings", size=10)
        )
        
        return layout
    
    def update_header(self) -> Panel:
        """Update the header panel."""
        uptime = time.time() - self.start_time
        uptime_str = str(timedelta(seconds=int(uptime)))
        
        return Panel(
            f"[bold blue]wpgarlic[/bold blue] | "
            f"Plugin: [green]{self.current_plugin}[/green] | "
            f"Endpoint: [green]{self.current_endpoint}[/green] | "
            f"Uptime: [yellow]{uptime_str}[/yellow]",
            box=box.ROUNDED
        )
    
    def update_stats_panel(self) -> Panel:
        """Update the statistics panel."""
        stats = self.feedback_engine.stats
        table = Table(show_header=False, box=box.SIMPLE)
        table.add_column("Metric", style="cyan", width=20)
        table.add_column("Value", style="green", justify="right")
        
        table.add_row("Total Executions", f"{stats.total_executions:,}")
        table.add_row("Executions/sec", f"{stats.executions_per_second:.1f}")
        table.add_row("Total Coverage", f"{stats.total_coverage:,}")
        table.add_row("Crashes Found", f"{stats.crashes_found:,}")
        table.add_row("Unique Crashes", f"{stats.unique_crashes:,}")
        table.add_row("Queue Size", f"{len(self.feedback_engine.input_queue):,}")
        table.add_row("Test Cases", f"{len(self.feedback_engine.test_cases):,}")
        
        return Panel(table, title="Statistics", border_style="blue")
    
    def update_coverage_panel(self) -> Panel:
        """Update the coverage panel."""
        coverage_map = self.feedback_engine.coverage_map
        
        if not coverage_map:
            return Panel("No coverage data available", title="Code Coverage", border_style="yellow")
        
        # Create coverage tree
        tree = Tree("Code Coverage")
        
        total_lines = sum(len(lines) for lines in coverage_map.values())
        
        for file_path, lines in list(coverage_map.items())[:10]:  # Show top 10 files
            file_name = file_path.split("/")[-1]
            coverage_percent = len(lines) / max(1, total_lines) * 100
            
            file_node = tree.add(f"[green]{file_name}[/green] ({len(lines)} lines)")
            file_node.add(f"Coverage: {coverage_percent:.1f}%")
        
        if len(coverage_map) > 10:
            tree.add(f"[dim]... and {len(coverage_map) - 10} more files[/dim]")
        
        return Panel(tree, title="Code Coverage", border_style="green")
    
    def update_crashes_panel(self) -> Panel:
        """Update the crashes panel."""
        crashes = []
        
        # Collect recent crashes
        for test_case in self.feedback_engine.test_cases.values():
            if test_case.crash_info:
                crashes.append(test_case.crash_info)
        
        if not crashes:
            return Panel("No crashes found", title="Crashes", border_style="green")
        
        # Sort by timestamp (newest first)
        crashes.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
        
        table = Table(show_header=True, box=box.SIMPLE)
        table.add_column("Type", style="cyan", width=15)
        table.add_column("Severity", style="red", width=10)
        table.add_column("Time", style="dim", width=8)
        
        for crash in crashes[:5]:  # Show top 5 crashes
            severity = crash.get("severity", "unknown")
            crash_type = crash.get("type", "unknown")
            timestamp = crash.get("timestamp", 0)
            
            if timestamp:
                time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")
            else:
                time_str = "Unknown"
            
            severity_color = {
                CrashSeverity.LOW: "yellow",
                CrashSeverity.MEDIUM: "orange1",
                CrashSeverity.HIGH: "red1",
                CrashSeverity.CRITICAL: "bright_red"
            }.get(severity, "white")
            
            table.add_row(
                crash_type,
                f"[{severity_color}]{severity.value.upper()}[/{severity_color}]",
                time_str
            )
        
        return Panel(table, title="Recent Crashes", border_style="red")
    
    def update_progress_panel(self, current_test: Optional[TestCase] = None) -> Panel:
        """Update the progress panel."""
        stats = self.feedback_engine.stats
        
        # Calculate progress percentage
        max_executions = self.feedback_engine.config.get("max_executions", 100000)
        progress_percent = min(100, (stats.total_executions / max_executions) * 100)
        
        progress_text = Text()
        progress_text.append("Overall Progress\n", style="bold")
        progress_text.append(f"Executions: {stats.total_executions:,} / {max_executions:,}\n")
        progress_text.append(f"Progress: {progress_percent:.1f}%\n")
        
        if current_test:
            progress_text.append(f"\nCurrent Test:\n", style="bold")
            progress_text.append(f"Payload: {str(current_test.payload)[:50]}...\n")
            progress_text.append(f"Fitness: {current_test.fitness_score:.3f}\n")
            progress_text.append(f"Mutations: {len(current_test.mutation_path)}\n")
        
        return Panel(progress_text, title="Progress", border_style="blue")
    
    def update_current_test_panel(self, test_case: Optional[TestCase] = None) -> Panel:
        """Update the current test panel."""
        if not test_case:
            return Panel("No test case active", title="Current Test", border_style="dim")
        
        content = Text()
        content.append("Payload:\n", style="bold")
        payload_str = str(test_case.payload)
        if len(payload_str) > 100:
            payload_str = payload_str[:100] + "..."
        content.append(f"{payload_str}\n\n")
        
        content.append("Coverage:\n", style="bold")
        content.append(f"  Unique paths: {len(test_case.coverage.unique_paths)}\n")
        content.append(f"  Execution time: {test_case.coverage.execution_time:.3f}s\n")
        content.append(f"  Memory usage: {test_case.coverage.memory_usage:,} bytes\n\n")
        
        content.append("Mutation Path:\n", style="bold")
        if test_case.mutation_path:
            path_str = " → ".join([m.value for m in test_case.mutation_path[-5:]])  # Last 5 mutations
            content.append(f"{path_str}\n")
        else:
            content.append("Initial test case\n")
        
        return Panel(content, title="Current Test", border_style="green")
    
    def update_recent_findings_panel(self) -> Panel:
        """Update the recent findings panel."""
        findings = []
        
        # Collect recent interesting findings
        for test_case in self.feedback_engine.test_cases.values():
            if test_case.crash_info or test_case.fitness_score > 0.5:
                findings.append(test_case)
        
        if not findings:
            return Panel("No interesting findings yet", title="Recent Findings", border_style="dim")
        
        # Sort by fitness score
        findings.sort(key=lambda x: x.fitness_score, reverse=True)
        
        table = Table(show_header=True, box=box.SIMPLE)
        table.add_column("Type", style="cyan", width=12)
        table.add_column("Fitness", style="green", width=8)
        table.add_column("Payload", style="white", width=30)
        
        for finding in findings[:5]:  # Show top 5 findings
            finding_type = "Crash" if finding.crash_info else "Interesting"
            fitness = f"{finding.fitness_score:.3f}"
            payload = str(finding.payload)[:30] + "..." if len(str(finding.payload)) > 30 else str(finding.payload)
            
            table.add_row(finding_type, fitness, payload)
        
        return Panel(table, title="Recent Findings", border_style="yellow")
    
    def update_footer(self) -> Panel:
        """Update the footer panel."""
        stats = self.feedback_engine.stats
        
        footer_text = Text()
        footer_text.append("Status: ", style="bold")
        
        if stats.crashes_found > 0:
            footer_text.append("CRASHES DETECTED", style="bright_red bold")
        elif stats.total_executions > 0:
            footer_text.append("FUZZING ACTIVE", style="green bold")
        else:
            footer_text.append("INITIALIZING", style="yellow bold")
        
        footer_text.append(" | ")
        footer_text.append(f"Last crash: ", style="bold")
        
        if stats.last_crash_time > 0:
            last_crash = datetime.fromtimestamp(stats.last_crash_time)
            footer_text.append(f"{last_crash.strftime('%H:%M:%S')}", style="red")
        else:
            footer_text.append("None", style="dim")
        
        return Panel(footer_text, box=box.ROUNDED)
    
    def show_live_interface(self, update_callback=None):
        """Show the live updating interface."""
        layout = self.create_layout()
        
        with Live(layout, console=self.console, refresh_per_second=2) as live:
            while True:
                try:
                    # Update all panels
                    layout["header"].update(self.update_header())
                    layout["stats"].update(self.update_stats_panel())
                    layout["coverage"].update(self.update_coverage_panel())
                    layout["crashes"].update(self.update_crashes_panel())
                    layout["progress"].update(self.update_progress_panel())
                    layout["current_test"].update(self.update_current_test_panel())
                    layout["recent_findings"].update(self.update_recent_findings_panel())
                    layout["footer"].update(self.update_footer())
                    
                    # Call update callback if provided
                    if update_callback:
                        update_callback()
                    
                    time.sleep(self.update_interval)
                    
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    self.console.print(f"[red]Error updating UI: {e}[/red]")
                    time.sleep(1)
    
    def show_crash_details(self, crash_info: Dict[str, Any]):
        """Show detailed crash information."""
        self.console.clear()
        
        # Crash header
        severity = crash_info.get("severity", "unknown")
        crash_type = crash_info.get("type", "unknown")
        timestamp = crash_info.get("timestamp", 0)
        
        severity_color = {
            CrashSeverity.LOW: "yellow",
            CrashSeverity.MEDIUM: "orange1", 
            CrashSeverity.HIGH: "red1",
            CrashSeverity.CRITICAL: "bright_red"
        }.get(severity, "white")
        
        header = Panel(
            f"[bold red]CRASH DETECTED[/bold red]\n"
            f"Type: [cyan]{crash_type}[/cyan]\n"
            f"Severity: [{severity_color}]{severity.value.upper()}[/{severity_color}]\n"
            f"Time: [dim]{datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')}[/dim]",
            title="Crash Analysis",
            border_style="red"
        )
        
        self.console.print(header)
        
        # Crash output
        crash_output = crash_info.get("output", "")
        if crash_output:
            syntax = Syntax(crash_output, "text", theme="monokai", line_numbers=True)
            output_panel = Panel(syntax, title="Crash Output", border_style="red")
            self.console.print(output_panel)
        
        self.console.print("\n[dim]Press any key to continue...[/dim]")
        input()
    
    def show_final_report(self):
        """Show final fuzzing report."""
        self.console.clear()
        
        stats = self.feedback_engine.stats
        
        # Summary panel
        summary = Panel(
            f"[bold blue]Fuzzing Session Complete[/bold blue]\n\n"
            f"Plugin: [green]{self.current_plugin}[/green]\n"
            f"Duration: [yellow]{timedelta(seconds=int(stats.uptime))}[/yellow]\n"
            f"Total Executions: [cyan]{stats.total_executions:,}[/cyan]\n"
            f"Average Speed: [green]{stats.executions_per_second:.1f} exec/sec[/green]\n"
            f"Total Coverage: [blue]{stats.total_coverage:,} lines[/blue]\n"
            f"Crashes Found: [red]{stats.crashes_found:,}[/red]\n"
            f"Unique Crashes: [red]{stats.unique_crashes:,}[/red]",
            title="Session Summary",
            border_style="blue"
        )
        
        self.console.print(summary)
        
        # Top crashes
        if stats.crashes_found > 0:
            crashes = []
            for test_case in self.feedback_engine.test_cases.values():
                if test_case.crash_info:
                    crashes.append(test_case.crash_info)
            
            crashes.sort(key=lambda x: x.get("timestamp", 0), reverse=True)
            
            crash_table = Table(title="Top Crashes", box=box.ROUNDED)
            crash_table.add_column("Type", style="cyan")
            crash_table.add_column("Severity", style="red")
            crash_table.add_column("Time", style="dim")
            crash_table.add_column("Payload", style="white")
            
            for crash in crashes[:10]:
                severity = crash.get("severity", "unknown")
                crash_type = crash.get("type", "unknown")
                timestamp = crash.get("timestamp", 0)
                
                if timestamp:
                    time_str = datetime.fromtimestamp(timestamp).strftime("%H:%M:%S")
                else:
                    time_str = "Unknown"
                
                # Find the test case with this crash
                payload = "Unknown"
                for test_case in self.feedback_engine.test_cases.values():
                    if test_case.crash_info == crash:
                        payload = str(test_case.payload)[:50]
                        break
                
                severity_color = {
                    CrashSeverity.LOW: "yellow",
                    CrashSeverity.MEDIUM: "orange1",
                    CrashSeverity.HIGH: "red1", 
                    CrashSeverity.CRITICAL: "bright_red"
                }.get(severity, "white")
                
                crash_table.add_row(
                    crash_type,
                    f"[{severity_color}]{severity.value.upper()}[/{severity_color}]",
                    time_str,
                    payload
                )
            
            self.console.print(crash_table)
        
        self.console.print("\n[green]Fuzzing session completed successfully![/green]")
    
    def print_status(self, message: str, style: str = "white"):
        """Print a status message."""
        self.console.print(f"[{style}]{message}[/{style}]")
    
    def print_error(self, message: str):
        """Print an error message."""
        self.console.print(f"[red]Error: {message}[/red]")
    
    def print_warning(self, message: str):
        """Print a warning message."""
        self.console.print(f"[yellow]Warning: {message}[/yellow]")
    
    def print_success(self, message: str):
        """Print a success message."""
        self.console.print(f"[green]Success: {message}[/green]")
