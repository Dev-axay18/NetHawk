"""
Console UI Helpers
"""

# ANSI Color Codes
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
RED = "\033[91m"
RESET = "\033[0m"
BOLD = "\033[1m"
GRAY = "\033[90m"


def success(message):
    """Print success message"""
    print(f"{GREEN}[✓]{RESET} {message}")


def info(message):
    """Print info message"""
    print(f"{CYAN}[i]{RESET} {message}")


def warning(message):
    """Print warning message"""
    print(f"{YELLOW}[!]{RESET} {message}")


def error(message):
    """Print error message"""
    print(f"{RED}[✗]{RESET} {message}")


def section_header(title):
    """Print section header"""
    print(f"\n{BOLD}{BLUE}{'='*60}{RESET}")
    print(f"{BOLD}{BLUE}{title.center(60)}{RESET}")
    print(f"{BOLD}{BLUE}{'='*60}{RESET}\n")


def print_table(headers, rows):
    """Print formatted table"""
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))
    
    header_line = " | ".join(h.ljust(col_widths[i]) for i, h in enumerate(headers))
    print(f"{BOLD}{header_line}{RESET}")
    print("-" * len(header_line))
    
    for row in rows:
        print(" | ".join(str(cell).ljust(col_widths[i]) for i, cell in enumerate(row)))
