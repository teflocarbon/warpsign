import json
import difflib
import datetime
import base64
from typing import Dict, Any, Union, List, Tuple, Optional
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table
from rich.columns import Columns
from rich.text import Text
from rich import box


def plist_to_diffable_dict(plist_obj):
    """
    Convert a plist object to a diffable dict, handling special types like Data.

    Args:
        plist_obj: A plist object which may contain binary data, dates, etc.

    Returns:
        A dict/list structure with all special types converted to string representations
    """
    if isinstance(plist_obj, dict):
        return {k: plist_to_diffable_dict(v) for k, v in plist_obj.items()}
    elif isinstance(plist_obj, list):
        return [plist_to_diffable_dict(item) for item in plist_obj]
    elif isinstance(plist_obj, bytes):
        # Convert binary data to base64 for diffing
        try:
            # Try to decode as UTF-8 string if possible
            return (
                f"<binary: {plist_obj.decode('utf-8')[:50]}...>"
                if len(plist_obj) > 50
                else f"<binary: {plist_obj.decode('utf-8')}>"
            )
        except UnicodeDecodeError:
            # Fall back to base64 representation
            b64 = base64.b64encode(plist_obj).decode("ascii")
            return f"<binary: {b64[:50]}...>" if len(b64) > 50 else f"<binary: {b64}>"
    elif isinstance(plist_obj, datetime.datetime):
        # Convert datetime to string
        return f"<datetime: {plist_obj.isoformat()}>"
    else:
        # Return other types as is
        return plist_obj


def create_json_diff(
    original: Dict[str, Any],
    modified: Dict[str, Any],
    original_label: str = "Original",
    modified_label: str = "Modified",
) -> List[str]:
    """
    Create a colored diff between two JSON objects.

    Args:
        original: Original JSON dictionary
        modified: Modified JSON dictionary
        original_label: Label for original content in diff header
        modified_label: Label for modified content in diff header

    Returns:
        List of strings with rich formatting for diff output
    """
    # Format JSON strings with stable sorting of keys for consistent diffs
    original_json = json.dumps(original, indent=4, sort_keys=True).splitlines()
    modified_json = json.dumps(modified, indent=4, sort_keys=True).splitlines()

    # Generate unified diff
    diff = list(
        difflib.unified_diff(
            original_json,
            modified_json,
            fromfile=original_label,
            tofile=modified_label,
            lineterm="",
        )
    )

    if not diff:
        return ["[yellow]No differences found between JSON objects[/]"]

    # Process diff to add rich formatting
    formatted_diff = []
    for line in diff:
        if line.startswith("+") and not line.startswith("+++"):
            formatted_diff.append(f"[green]{line}[/green]")
        elif line.startswith("-") and not line.startswith("---"):
            formatted_diff.append(f"[red]{line}[/red]")
        elif line.startswith("@@"):
            formatted_diff.append(f"[cyan]{line}[/cyan]")
        else:
            formatted_diff.append(line)

    return formatted_diff


def print_json_diff(
    console: Console,
    original: Dict[str, Any],
    modified: Dict[str, Any],
    original_label: str = "Original",
    modified_label: str = "Modified",
) -> None:
    """
    Print a colored diff between two JSON objects to the console.

    Args:
        console: Rich console to print to
        original: Original JSON dictionary
        modified: Modified JSON dictionary
        original_label: Label for original content in diff header
        modified_label: Label for modified content in diff header
    """
    # Create visual diff with icons
    original_json = json.dumps(original, indent=4, sort_keys=True)
    modified_json = json.dumps(modified, indent=4, sort_keys=True)

    # Create a title with summary of changes
    added_keys = set(modified.keys()) - set(original.keys())
    removed_keys = set(original.keys()) - set(modified.keys())
    modified_keys = set(
        k for k in original.keys() & modified.keys() if original[k] != modified[k]
    )

    # Build summary
    change_summary = []
    if added_keys:
        change_summary.append(f"[green]Added[/]: {len(added_keys)}")
    if removed_keys:
        change_summary.append(f"[red]Removed[/]: {len(removed_keys)}")
    if modified_keys:
        change_summary.append(f"[yellow]Modified[/]: {len(modified_keys)}")

    summary_text = (
        " | ".join(change_summary) if change_summary else "No changes detected"
    )

    # Create a table to display the diff
    table = Table(
        box=box.ROUNDED,
        expand=True,
        border_style="blue",
        header_style="bold cyan",
        title=f"JSON Diff ({summary_text})",
    )

    # Add columns with highlighting (removed the Line column)
    table.add_column("Change", width=3)
    table.add_column("Content", overflow="fold")

    # Format each line of the diff
    formatted_diff = create_json_diff(
        original, modified, original_label, modified_label
    )

    for line in formatted_diff:
        if line.startswith("[green]+"):
            # Extract the content after the + sign
            content = line.replace("[green]+", "").replace("[/green]", "")
            table.add_row(
                "+++",
                Text(content, style="green"),
            )
        elif line.startswith("[red]-"):
            # Extract the content after the - sign
            content = line.replace("[red]-", "").replace("[/red]", "")
            table.add_row(
                "---",
                Text(content, style="red"),
            )
        elif line.startswith("[cyan]@@"):
            # Format hunk headers
            content = line.replace("[cyan]", "").replace("[/cyan]", "")
            table.add_row("🔍", Text(content, style="cyan dim"))
        elif not (line.startswith("+++") or line.startswith("---")):
            # Regular context lines
            table.add_row("", Text(line))

    # Show detailed key differences
    if added_keys or removed_keys or modified_keys:
        panels = []

        if added_keys:
            added_content = "\n".join([f"  • {k}" for k in sorted(added_keys)])
            panels.append(
                Panel(added_content, title="Added Keys", border_style="green")
            )

        if removed_keys:
            removed_content = "\n".join([f"  • {k}" for k in sorted(removed_keys)])
            panels.append(
                Panel(removed_content, title="Removed Keys", border_style="red")
            )

        if modified_keys:
            modified_content = "\n".join([f"  • {k}" for k in sorted(modified_keys)])
            panels.append(
                Panel(modified_content, title="Modified Keys", border_style="yellow")
            )

        # Print the table and key differences
        console.print(table)
        console.print(Columns(panels))
    else:
        # Just print the table if no key differences
        console.print(table)
