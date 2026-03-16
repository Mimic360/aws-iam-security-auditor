from auditor.iam_checks import (
    check_mfa_enabled,
    check_inactive_users,
    check_old_access_keys,
    check_admin_policy_attached,
    check_root_account_activity,
    check_dual_access_users,
    check_password_policy,
)
from auditor.report import print_terminal_report, save_json_report


def run_audit():
    print("\nStarting AWS IAM Security Audit...")
    print("This may take a moment depending on account size.\n")

    checks = [
        check_mfa_enabled,
        check_inactive_users,
        check_old_access_keys,
        check_admin_policy_attached,
        check_root_account_activity,
        check_dual_access_users,
        check_password_policy,
    ]

    results = []
    for check in checks:
        print(f"  Checking: {check.__name__}...")
        results.append(check())

    print_terminal_report(results)

    path = save_json_report(results)
    print(f"Full JSON report saved to: {path}\n")


if __name__ == "__main__":
    run_audit()
