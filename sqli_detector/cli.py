import sys
import argparse
from pathlib import Path
from colorama import Fore, Style, init

from .analyzer import analyze_file, analyze_directory

# Initialize colorama for Windows support
init()


def print_banner():
    """Print tool banner."""
    banner = f"""
{Fore.CYAN}===============================================================
          SQL Injection Detector v0.2.0
     Static Analysis Tool for Python Code Security
==============================================================={Style.RESET_ALL}
"""
    print(banner)


def print_finding(finding, index):
    """Pretty print a finding."""
    severity_color = Fore.RED if "injection" in finding.vulnerability_type.lower() else Fore.YELLOW

    print(f"\n{severity_color}[{index}] {finding.vulnerability_type.upper()}{Style.RESET_ALL}")
    print(f"  {Fore.WHITE}File:{Style.RESET_ALL} {finding.filename}:{finding.line}")
    print(f"  {Fore.WHITE}Code:{Style.RESET_ALL} {Fore.YELLOW}{finding.code}{Style.RESET_ALL}")
    print(f"  {Fore.GREEN}Fix:{Style.RESET_ALL}  {finding.recommendation}")


def scan_command(args):
    """Handle scan command."""
    target_path = Path(args.path)

    if not target_path.exists():
        print(f"{Fore.RED}Error: Path '{target_path}' does not exist{Style.RESET_ALL}")
        return 1

    print(f"{Fore.CYAN}Scanning: {target_path}{Style.RESET_ALL}\n")

    # Analyze target
    if target_path.is_file():
        findings = analyze_file(target_path)
        results = {str(target_path): findings} if findings else {}
    else:
        results = analyze_directory(target_path)

    # Print results
    total_findings = sum(len(findings) for findings in results.values())

    if total_findings == 0:
        print(f"{Fore.GREEN}[OK] No SQL injection vulnerabilities found!{Style.RESET_ALL}")
        return 0

    print(f"{Fore.YELLOW}Found {total_findings} potential vulnerabilities:\n{Style.RESET_ALL}")

    finding_index = 1
    for filepath, findings in results.items():
        for finding in findings:
            print_finding(finding, finding_index)
            finding_index += 1

    # Summary
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.RED}Total vulnerabilities found: {total_findings}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}Files analyzed: {len(results)}{Style.RESET_ALL}")

    return 1 if total_findings > 0 else 0


def main():
    """CLI entry point."""
    parser = argparse.ArgumentParser(
        description="SQL Injection Detector - Find SQL injection vulnerabilities in Python code",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Scan command
    scan_parser = subparsers.add_parser('scan', help='Scan Python files for SQL injection vulnerabilities')
    scan_parser.add_argument('path', type=str, help='Path to Python file or directory to scan')
    scan_parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        return 0

    print_banner()

    if args.command == 'scan':
        return scan_command(args)

    return 0


if __name__ == '__main__':
    sys.exit(main())
