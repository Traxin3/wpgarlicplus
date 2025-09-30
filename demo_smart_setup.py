#!/usr/bin/env python3
"""
Demo script showing the smart setup UI in action.
"""

import time
import sys
import os

# Add the parent directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from setup_manager import SmartSetupManager, run_smart_setup
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich import box
import sys


def demo_first_run():
    """Demo the first-time setup experience."""
    console = Console()
    
    console.print("\n[bold blue]🧄 wpgarlic Smart Setup Demo - First Run[/bold blue]\n")
    
    # Simulate first run
    manager = SmartSetupManager()
    
    # Show welcome screen
    manager.show_welcome_screen("demo-plugin", "1.0.0")
    
    # Simulate setup steps
    console.print("[yellow]Press Enter to continue with setup simulation...[/yellow]")
    input()
    
    # Show setup progress (simulated)
    console.print("[blue]Running smart setup simulation...[/blue]")
    time.sleep(2)
    
    # Show completion
    manager.show_setup_summary("demo-plugin", "1.0.0")
    
    console.print("[green]✅ First run demo completed![/green]\n")


def demo_subsequent_run():
    """Demo the subsequent run experience."""
    console = Console()
    
    console.print("\n[bold blue]🧄 wpgarlic Smart Setup Demo - Subsequent Run[/bold blue]\n")
    
    # Simulate subsequent run
    manager = SmartSetupManager()
    
    # Show welcome screen (will show cached status)
    manager.show_welcome_screen("demo-plugin", "1.0.0")
    
    console.print("[yellow]Press Enter to continue with cached setup simulation...[/yellow]")
    input()
    
    # Show setup progress (faster, cached)
    console.print("[blue]Running cached setup simulation...[/blue]")
    time.sleep(1)
    
    # Show completion
    manager.show_setup_summary("demo-plugin", "1.0.0")
    
    console.print("[green]✅ Subsequent run demo completed![/green]\n")


def demo_setup_stats():
    """Demo the setup statistics."""
    console = Console()
    
    console.print("\n[bold blue]🧄 wpgarlic Smart Setup Demo - Statistics[/bold blue]\n")
    
    manager = SmartSetupManager()
    stats = manager.get_setup_stats()
    
    # Create a demo stats table
    from rich.table import Table
    
    table = Table(title="📊 Setup Statistics", box=box.ROUNDED)
    table.add_column("Metric", style="cyan", width=20)
    table.add_column("Value", style="green", width=15)
    
    table.add_row("Total Setups", "15")
    table.add_row("Successful Setups", "14")
    table.add_row("Success Rate", "93.3%")
    table.add_row("Average Duration", "45.2s")
    table.add_row("Cached Plugins", "8")
    
    console.print(table)
    console.print("[green]✅ Statistics demo completed![/green]\n")


def main():
    """Run the demo."""
    # Configure console for Windows compatibility
    console = Console(force_terminal=True, legacy_windows=False)
    
    # Welcome banner
    welcome_text = Text()
    welcome_text.append("🧄 wpgarlic Smart Setup Manager\n", style="bold blue")
    welcome_text.append("Enhanced WordPress Plugin Fuzzer Setup\n\n", style="cyan")
    welcome_text.append("This demo showcases the smart setup features:\n", style="yellow")
    welcome_text.append("• First-time initialization with full setup\n", style="white")
    welcome_text.append("• Subsequent runs with intelligent caching\n", style="white")
    welcome_text.append("• Setup statistics and history tracking\n", style="white")
    welcome_text.append("• Progress visualization with Rich UI\n", style="white")
    
    welcome_panel = Panel(
        Align.center(welcome_text),
        title="🚀 Smart Setup Demo",
        border_style="blue",
        padding=(2, 4)
    )
    
    console.print(welcome_panel)
    console.print()
    
    # Demo options
    console.print("[bold]Demo Options:[/bold]")
    console.print("1. First-time setup experience")
    console.print("2. Subsequent run (cached) experience") 
    console.print("3. Setup statistics and history")
    console.print("4. Run all demos")
    console.print("5. Exit")
    console.print()
    
    while True:
        try:
            choice = input("Select demo (1-5): ").strip()
            
            if choice == "1":
                demo_first_run()
            elif choice == "2":
                demo_subsequent_run()
            elif choice == "3":
                demo_setup_stats()
            elif choice == "4":
                demo_first_run()
                demo_subsequent_run()
                demo_setup_stats()
            elif choice == "5":
                console.print("[green]Goodbye! 👋[/green]")
                break
            else:
                console.print("[red]Invalid choice. Please select 1-5.[/red]")
                
        except KeyboardInterrupt:
            console.print("\n[yellow]Demo interrupted by user[/yellow]")
            break
        except Exception as e:
            console.print(f"[red]Demo error: {e}[/red]")


if __name__ == "__main__":
    main()
