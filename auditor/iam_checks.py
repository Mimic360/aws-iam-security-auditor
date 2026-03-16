import csv
import io
import time
from datetime import datetime, timezone

from config import get_iam_client


def _all_users(iam):
    # IAM list_users is paginated, this flattens all pages into one list
    users = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        users.extend(page["Users"])
    return users


def _days_since(dt):
    # takes a timezone-aware datetime, returns days elapsed
    return (datetime.now(timezone.utc) - dt).days


def check_mfa_enabled():
    # CIS 1.10, any user without MFA is one stolen password away from a breach
    iam = get_iam_client()
    try:
        no_mfa = [
            u["UserName"]
            for u in _all_users(iam)
            if not iam.list_mfa_devices(UserName=u["UserName"])["MFADevices"]
        ]

        if no_mfa:
            return {
                "check_name": "MFA Not Enabled",
                "status": "FAIL",
                "severity": "HIGH",
                "affected_resources": no_mfa,
                "detail": f"{len(no_mfa)} user(s) have no MFA device. A stolen password alone grants full access.",
            }
        return {
            "check_name": "MFA Not Enabled",
            "status": "PASS",
            "severity": "HIGH",
            "affected_resources": [],
            "detail": "All users have MFA enabled.",
        }
    except Exception as e:
        return _error_result("MFA Not Enabled", "HIGH", e)


def check_inactive_users():
    # CIS 1.3, dormant accounts are forgotten attack surfaces
    # Users who have never logged in are measured from account creation date
    iam = get_iam_client()
    try:
        inactive = []
        for user in _all_users(iam):
            last_login = user.get("PasswordLastUsed")
            reference_date = last_login if last_login else user["CreateDate"]
            if _days_since(reference_date) >= 90:
                inactive.append(user["UserName"])

        if inactive:
            return {
                "check_name": "Inactive Users (90+ Days)",
                "status": "FAIL",
                "severity": "MEDIUM",
                "affected_resources": inactive,
                "detail": f"{len(inactive)} user(s) haven't logged in for 90+ days. Disable or delete them.",
            }
        return {
            "check_name": "Inactive Users (90+ Days)",
            "status": "PASS",
            "severity": "MEDIUM",
            "affected_resources": [],
            "detail": "All users have logged in within the last 90 days.",
        }
    except Exception as e:
        return _error_result("Inactive Users (90+ Days)", "MEDIUM", e)


def check_old_access_keys():
    # CIS 1.14, long-lived keys are a liability, rotate every 90 days
    iam = get_iam_client()
    try:
        old_keys = []
        for user in _all_users(iam):
            for key in iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]:
                if key["Status"] == "Active" and _days_since(key["CreateDate"]) >= 90:
                    age = _days_since(key["CreateDate"])
                    old_keys.append(f"{user['UserName']} (key {key['AccessKeyId'][:8]}..., {age}d old)")

        if old_keys:
            return {
                "check_name": "Access Keys Not Rotated (90+ Days)",
                "status": "FAIL",
                "severity": "HIGH",
                "affected_resources": old_keys,
                "detail": f"{len(old_keys)} active key(s) are overdue for rotation.",
            }
        return {
            "check_name": "Access Keys Not Rotated (90+ Days)",
            "status": "PASS",
            "severity": "HIGH",
            "affected_resources": [],
            "detail": "All active access keys are under 90 days old.",
        }
    except Exception as e:
        return _error_result("Access Keys Not Rotated (90+ Days)", "HIGH", e)


def check_admin_policy_attached():
    # AdministratorAccess = full AWS access with no restrictions
    # It has no place on regular users or application roles
    iam = get_iam_client()
    admin_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    try:
        flagged = []

        for user in _all_users(iam):
            policies = iam.list_attached_user_policies(UserName=user["UserName"])["AttachedPolicies"]
            if any(p["PolicyArn"] == admin_arn for p in policies):
                flagged.append(f"user:{user['UserName']}")

        paginator = iam.get_paginator("list_roles")
        for page in paginator.paginate():
            for role in page["Roles"]:
                policies = iam.list_attached_role_policies(RoleName=role["RoleName"])["AttachedPolicies"]
                if any(p["PolicyArn"] == admin_arn for p in policies):
                    flagged.append(f"role:{role['RoleName']}")

        if flagged:
            return {
                "check_name": "AdministratorAccess Policy Attached",
                "status": "FAIL",
                "severity": "HIGH",
                "affected_resources": flagged,
                "detail": f"{len(flagged)} principal(s) have unrestricted AdministratorAccess. Scope these down.",
            }
        return {
            "check_name": "AdministratorAccess Policy Attached",
            "status": "PASS",
            "severity": "HIGH",
            "affected_resources": [],
            "detail": "No users or roles have AdministratorAccess attached.",
        }
    except Exception as e:
        return _error_result("AdministratorAccess Policy Attached", "HIGH", e)


def check_root_account_activity():
    # Root has unconditional access, it can't be restricted by IAM policies
    # it should never have access keys and should rarely be used
    iam = get_iam_client()
    try:
        # AWS generates this report async, poll until ready
        iam.generate_credential_report()
        for _ in range(10):
            response = iam.get_credential_report()
            if response["ReportFormat"] == "text/csv":
                break
            time.sleep(1)

        content = response["Content"].decode("utf-8")
        reader = csv.DictReader(io.StringIO(content))

        for row in reader:
            if row["user"] != "<root_account>":
                continue

            # active root access keys are an immediate critical finding
            key1_active = row.get("access_key_1_active") == "true"
            key2_active = row.get("access_key_2_active") == "true"
            if key1_active or key2_active:
                return {
                    "check_name": "Root Account Activity",
                    "status": "FAIL",
                    "severity": "HIGH",
                    "affected_resources": ["<root_account>"],
                    "detail": "Root has active programmatic access keys. Delete them immediately.",
                }

            last_login = row.get("password_last_used", "")
            if last_login not in ("N/A", "no_information", ""):
                try:
                    login_dt = datetime.strptime(last_login[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
                    days_ago = _days_since(login_dt)
                    if days_ago <= 90:
                        return {
                            "check_name": "Root Account Activity",
                            "status": "FAIL",
                            "severity": "HIGH",
                            "affected_resources": ["<root_account>"],
                            "detail": f"Root was used {days_ago} day(s) ago ({last_login}). Use a least-privilege IAM user instead.",
                        }
                except ValueError:
                    pass

            return {
                "check_name": "Root Account Activity",
                "status": "PASS",
                "severity": "HIGH",
                "affected_resources": [],
                "detail": f"Root has no active keys and last login was: {last_login or 'never'}.",
            }

        return _error_result("Root Account Activity", "HIGH", "Root account row not found in credential report.")
    except Exception as e:
        return _error_result("Root Account Activity", "HIGH", e)


def check_dual_access_users():
    # users who only need the console don't need API keys and vice versa
    # dual access doubles the attack surface for no reason
    iam = get_iam_client()
    try:
        iam.generate_credential_report()
        for _ in range(10):
            response = iam.get_credential_report()
            if response["ReportFormat"] == "text/csv":
                break
            time.sleep(1)

        content = response["Content"].decode("utf-8")
        reader = csv.DictReader(io.StringIO(content))

        flagged = [
            row["user"]
            for row in reader
            if row["user"] != "<root_account>"
            and row.get("password_enabled") == "true"
            and (row.get("access_key_1_active") == "true" or row.get("access_key_2_active") == "true")
        ]

        if flagged:
            return {
                "check_name": "Dual Access (Console + Programmatic)",
                "status": "WARN",
                "severity": "MEDIUM",
                "affected_resources": flagged,
                "detail": f"{len(flagged)} user(s) have both console and API access. Confirm this is intentional.",
            }
        return {
            "check_name": "Dual Access (Console + Programmatic)",
            "status": "PASS",
            "severity": "MEDIUM",
            "affected_resources": [],
            "detail": "No users hold both console and programmatic access.",
        }
    except Exception as e:
        return _error_result("Dual Access (Console + Programmatic)", "MEDIUM", e)


def check_password_policy():
    # CIS 1.8-1.11, without a policy AWS enforces nothing
    # minimum bar: 14 chars, complexity, 90 day expiry
    iam = get_iam_client()
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        failures = []

        if policy.get("MinimumPasswordLength", 0) < 14:
            failures.append(f"Min length is {policy.get('MinimumPasswordLength', 'unset')} (need 14+)")
        if not policy.get("RequireUppercaseCharacters"):
            failures.append("Uppercase not required")
        if not policy.get("RequireLowercaseCharacters"):
            failures.append("Lowercase not required")
        if not policy.get("RequireNumbers"):
            failures.append("Numbers not required")
        if not policy.get("RequireSymbols"):
            failures.append("Symbols not required")

        max_age = policy.get("MaxPasswordAge")
        if not max_age or max_age > 90:
            failures.append(f"Max password age is {max_age or 'unset'} (need <=90 days)")

        if failures:
            return {
                "check_name": "Password Policy",
                "status": "FAIL",
                "severity": "MEDIUM",
                "affected_resources": failures,
                "detail": f"Password policy fails {len(failures)} CIS requirement(s).",
            }
        return {
            "check_name": "Password Policy",
            "status": "PASS",
            "severity": "MEDIUM",
            "affected_resources": [],
            "detail": "Password policy meets CIS benchmark minimums.",
        }

    except iam.exceptions.NoSuchEntityException:
        return {
            "check_name": "Password Policy",
            "status": "FAIL",
            "severity": "MEDIUM",
            "affected_resources": ["account-level password policy"],
            "detail": "No password policy configured. AWS enforces nothing by default.",
        }
    except Exception as e:
        return _error_result("Password Policy", "MEDIUM", e)


def _error_result(check_name, severity, error):
    # centralised fallback for checks that throw unexpected exceptions
    return {
        "check_name": check_name,
        "status": "WARN",
        "severity": severity,
        "affected_resources": [],
        "detail": f"Check could not complete: {error}",
    }
