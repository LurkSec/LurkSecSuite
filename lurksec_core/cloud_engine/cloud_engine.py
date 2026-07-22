import json
import subprocess
import time
from typing import List, Dict, Any


def _run_cli(cmd: str) -> str:
    try:
        return subprocess.check_output(cmd, shell=True, text=True, errors="ignore", timeout=10)
    except Exception:
        return ""


class AWSInspector:
    """
    AWS CLI-based security auditor for S3, EC2 Security Groups, and IAM.
    Gracefully degrades when AWS CLI is not configured.
    """

    @staticmethod
    def check_cli_available() -> bool:
        out = _run_cli("aws --version 2>&1")
        return "aws-cli" in out.lower() or "amazon" in out.lower()

    @staticmethod
    def get_s3_findings() -> List[Dict[str, Any]]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        findings = []
        out = _run_cli("aws s3api list-buckets --output json 2>&1")
        try:
            data = json.loads(out)
            buckets = data.get("Buckets", [])
            for bucket in buckets:
                name = bucket.get("Name", "")
                acl_out = _run_cli(f"aws s3api get-bucket-acl --bucket {name} --output json 2>&1")
                try:
                    acl_data = json.loads(acl_out)
                    grants = acl_data.get("Grants", [])
                    public_grants = [g for g in grants if "AllUsers" in str(g) or "AuthenticatedUsers" in str(g)]
                    if public_grants:
                        findings.append({
                            "timestamp": now, "resource_type": "S3 Bucket", "resource_id": name,
                            "severity": "HIGH", "status": "FAIL",
                            "finding": f"S3 bucket '{name}' has public ACL grants",
                            "recommendation": "Remove public ACL and enable Block Public Access"
                        })
                    else:
                        findings.append({
                            "timestamp": now, "resource_type": "S3 Bucket", "resource_id": name,
                            "severity": "LOW", "status": "PASS",
                            "finding": f"S3 bucket '{name}' is not publicly accessible",
                            "recommendation": "Continue monitoring bucket ACLs"
                        })
                except Exception:
                    pass
        except Exception:
            pass
        return findings

    @staticmethod
    def get_sg_findings() -> List[Dict[str, Any]]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        findings = []
        out = _run_cli("aws ec2 describe-security-groups --output json 2>&1")
        try:
            data = json.loads(out)
            groups = data.get("SecurityGroups", [])
            for sg in groups:
                sg_id = sg.get("GroupId", "")
                sg_name = sg.get("GroupName", "")
                for rule in sg.get("IpPermissions", []):
                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            from_port = rule.get("FromPort", "All")
                            to_port = rule.get("ToPort", "All")
                            findings.append({
                                "timestamp": now, "resource_type": "EC2 Security Group", "resource_id": sg_id,
                                "severity": "HIGH" if str(from_port) in ["22", "3389", "0"] else "MEDIUM",
                                "status": "FAIL",
                                "finding": f"Security Group '{sg_name}' ({sg_id}) allows 0.0.0.0/0 on port {from_port}-{to_port}",
                                "recommendation": "Restrict inbound rules to known CIDR ranges"
                            })
        except Exception:
            pass
        return findings

    @staticmethod
    def get_iam_findings() -> List[Dict[str, Any]]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        findings = []
        out = _run_cli("aws iam get-account-summary --output json 2>&1")
        try:
            data = json.loads(out)
            summary = data.get("SummaryMap", {})
            if summary.get("AccountMFAEnabled", 0) == 0:
                findings.append({
                    "timestamp": now, "resource_type": "IAM Account",
                    "resource_id": "Root Account",
                    "severity": "HIGH", "status": "FAIL",
                    "finding": "Root account MFA is NOT enabled",
                    "recommendation": "Enable MFA on the AWS root account immediately"
                })
            users_with_access_keys = summary.get("UsersWithAccessKeys", 0)
            if users_with_access_keys > 0:
                findings.append({
                    "timestamp": now, "resource_type": "IAM Users",
                    "resource_id": f"{users_with_access_keys} users",
                    "severity": "MEDIUM", "status": "WARN",
                    "finding": f"{users_with_access_keys} IAM users have access keys configured",
                    "recommendation": "Audit and rotate all IAM access keys regularly"
                })
        except Exception:
            pass
        return findings


class AzureInspector:
    """
    Azure CLI-based security auditor for NSGs and Storage Accounts.
    Gracefully degrades when Azure CLI is not configured.
    """

    @staticmethod
    def check_cli_available() -> bool:
        out = _run_cli("az --version 2>&1")
        return "azure-cli" in out.lower()

    @staticmethod
    def get_nsg_findings() -> List[Dict[str, Any]]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        findings = []
        out = _run_cli("az network nsg list --output json 2>&1")
        try:
            nsgs = json.loads(out)
            for nsg in nsgs:
                nsg_name = nsg.get("name", "")
                for rule in nsg.get("securityRules", []):
                    if rule.get("direction") == "Inbound" and rule.get("access") == "Allow":
                        if rule.get("sourceAddressPrefix") in ["*", "0.0.0.0/0", "Internet"]:
                            port = rule.get("destinationPortRange", "*")
                            findings.append({
                                "timestamp": now, "resource_type": "Azure NSG", "resource_id": nsg_name,
                                "severity": "HIGH" if port in ["22", "3389", "*"] else "MEDIUM",
                                "status": "FAIL",
                                "finding": f"NSG '{nsg_name}' allows Internet inbound on port {port}",
                                "recommendation": "Restrict NSG inbound rules to specific IP ranges"
                            })
        except Exception:
            pass
        return findings

    @staticmethod
    def get_storage_findings() -> List[Dict[str, Any]]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        findings = []
        out = _run_cli("az storage account list --output json 2>&1")
        try:
            accounts = json.loads(out)
            for acct in accounts:
                name = acct.get("name", "")
                allow_public = acct.get("allowBlobPublicAccess", False)
                if allow_public:
                    findings.append({
                        "timestamp": now, "resource_type": "Azure Storage Account", "resource_id": name,
                        "severity": "HIGH", "status": "FAIL",
                        "finding": f"Storage Account '{name}' has public blob access enabled",
                        "recommendation": "Disable allowBlobPublicAccess on all storage accounts"
                    })
        except Exception:
            pass
        return findings


class BaselineAuditor:
    """
    Checks local cloud CLI configuration baseline.
    """

    @staticmethod
    def audit() -> List[Dict[str, Any]]:
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        checks = []

        aws_available = AWSInspector.check_cli_available()
        checks.append({
            "audit_id": "CLOUD-001", "component": "AWS CLI Installation",
            "status": "PASS" if aws_available else "WARN",
            "value": "Installed" if aws_available else "Not Installed",
            "severity": "LOW" if aws_available else "MEDIUM",
            "recommendation": "Install AWS CLI for cloud security auditing"
        })

        azure_available = AzureInspector.check_cli_available()
        checks.append({
            "audit_id": "CLOUD-002", "component": "Azure CLI Installation",
            "status": "PASS" if azure_available else "WARN",
            "value": "Installed" if azure_available else "Not Installed",
            "severity": "LOW" if azure_available else "MEDIUM",
            "recommendation": "Install Azure CLI for cloud security auditing"
        })

        # Check AWS credentials file
        import os
        aws_creds = os.path.expanduser("~\\.aws\\credentials")
        checks.append({
            "audit_id": "CLOUD-003", "component": "AWS Credentials Configured",
            "status": "PASS" if os.path.isfile(aws_creds) else "WARN",
            "value": "Configured" if os.path.isfile(aws_creds) else "Not Configured",
            "severity": "LOW",
            "recommendation": "Run 'aws configure' to set up credentials"
        })

        return checks
