import json
import os
from datetime import datetime

# ANSI colour codes — makes the terminal output actually readable
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# Controls sort order in the terminal output — HIGH findings appear first
SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}


def _status_colour(status):
    return {
        "PASS": GREEN,
        "FAIL": RED,
        "WARN": YELLOW,
    }.get(status, RESET)


def _severity_colour(severity):
    return {
        "HIGH": RED,
        "MEDIUM": YELLOW,
        "LOW": CYAN,
    }.get(severity, RESET)


def save_json_report(results, output_dir="output"):
    os.makedirs(output_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H%M%S")
    filepath = os.path.join(output_dir, f"report_{timestamp}.json")

    report = {
        "generated_at": datetime.now().isoformat(),
        "total_checks": len(results),
        "summary": {
            "PASS": sum(1 for r in results if r["status"] == "PASS"),
            "FAIL": sum(1 for r in results if r["status"] == "FAIL"),
            "WARN": sum(1 for r in results if r["status"] == "WARN"),
        },
        "findings": results,
    }

    with open(filepath, "w") as f:
        json.dump(report, f, indent=2, default=str)

    return filepath


def print_terminal_report(results):
    passes   = [r for r in results if r["status"] == "PASS"]
    fails    = [r for r in results if r["status"] == "FAIL"]
    warns    = [r for r in results if r["status"] == "WARN"]

    # Sort non-passing findings so HIGH issues are at the top
    findings = sorted(fails + warns, key=lambda r: SEVERITY_ORDER.get(r["severity"], 9))

    print()
    print(f"{BOLD}{'=' * 60}{RESET}")
    print(f"{BOLD}  AWS IAM SECURITY AUDIT REPORT{RESET}")
    print(f"{BOLD}{'=' * 60}{RESET}")
    print(f"  Total checks : {len(results)}")
    print(f"  {GREEN}PASS{RESET}          : {len(passes)}")
    print(f"  {RED}FAIL{RESET}          : {len(fails)}")
    print(f"  {YELLOW}WARN{RESET}          : {len(warns)}")
    print(f"{BOLD}{'=' * 60}{RESET}")

    if findings:
        print(f"\n{BOLD}FINDINGS{RESET}\n")
        for r in findings:
            sc  = _status_colour(r["status"])
            svc = _severity_colour(r["severity"])
            print(f"  {sc}{BOLD}[{r['status']}]{RESET}  {svc}{r['severity']}{RESET}  {BOLD}{r['check_name']}{RESET}")
            print(f"         {r['detail']}")
            for resource in r["affected_resources"]:
                print(f"           - {resource}")
            print()

    if passes:
        print(f"{BOLD}PASSING{RESET}")
        for r in passes:
            print(f"  {GREEN}[PASS]{RESET}  {r['check_name']}")

    print(f"\n{BOLD}{'=' * 60}{RESET}\n")
