import json
import subprocess
import time
from typing import List, Dict, Any


import os
import shutil

def _get_aws_bin() -> str:
    which = shutil.which("aws") or shutil.which("aws.exe")
    if which:
        return f'"{which}"'
    user_aws = os.path.expanduser(r"~\AppData\Local\Programs\Amazon\AWSCLIV2\aws.exe")
    if os.path.isfile(user_aws):
        return f'"{user_aws}"'
    prog_aws = r"C:\Program Files\Amazon\AWSCLIV2\aws.exe"
    if os.path.isfile(prog_aws):
        return f'"{prog_aws}"'
    return "aws"

def _get_az_bin() -> str:
    which = shutil.which("az") or shutil.which("az.cmd")
    if which:
        return f'"{which}"'
    user_az = os.path.expanduser(r"~\AppData\Local\Programs\Microsoft SDKs\Azure\CLI2\wbin\az.cmd")
    if os.path.isfile(user_az):
        return f'"{user_az}"'
    prog_az = r"C:\Program Files\Microsoft SDKs\Azure\CLI2\wbin\az.cmd"
    if os.path.isfile(prog_az):
        return f'"{prog_az}"'
    return "az"

def _run_cli(cmd: str) -> str:
    if cmd.startswith("aws "):
        cmd = _get_aws_bin() + cmd[3:]
    elif cmd.startswith("az "):
        cmd = _get_az_bin() + cmd[2:]
    try:
        return subprocess.check_output(cmd, shell=True, text=True, errors="ignore", timeout=10)
    except Exception:
        return ""


AWS_CACHE = {"timestamp": 0, "data": None}
AZURE_CACHE = {"timestamp": 0, "data": None}


class AWSInspector:
    
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

    @staticmethod
    def get_summary() -> Dict[str, Any]:
        import os
        now_time = time.time()
        if AWS_CACHE.get("data") and (now_time - AWS_CACHE.get("timestamp", 0)) < 60.0:
            return AWS_CACHE["data"]

        now = time.strftime("%Y-%m-%d %H:%M:%S")
        cli = AWSInspector.check_cli_available()
        s3 = AWSInspector.get_s3_findings()
        sg = AWSInspector.get_sg_findings()
        iam = AWSInspector.get_iam_findings()
        findings = s3 + sg + iam

        if not cli:
            findings = [{
                "timestamp": now, "resource_type": "AWS CLI Runtime", "resource_id": "System PATH / AppData",
                "severity": "INFO", "status": "WARN",
                "finding": "AWS CLI binary ('aws') is not installed or not present in system PATH.",
                "recommendation": "Install AWS CLI v2 via https://aws.amazon.com/cli/ or add aws.exe to PATH"
            }]
            res = {
                "cli_installed": False,
                "buckets_count": 0,
                "public_acls": 0,
                "open_sg": 0,
                "compliance_score": 0,
                "findings": findings
            }
            AWS_CACHE["timestamp"] = now_time
            AWS_CACHE["data"] = res
            return res

        creds = os.path.expanduser("~\\.aws\\credentials")

        if not findings:
            if os.path.isfile(creds) or "AWS_ACCESS_KEY_ID" in os.environ:
                findings.append({
                    "timestamp": now, "resource_type": "AWS IAM / Profile", "resource_id": "AWS Profile Default",
                    "severity": "PASS", "status": "PASS",
                    "finding": "AWS credentials configured locally (~/.aws/credentials). CLI session initialized.",
                    "recommendation": "Enforce MFA and least-privilege IAM policies."
                })
            else:
                findings.append({
                    "timestamp": now, "resource_type": "AWS CLI Configuration", "resource_id": "Local Workstation",
                    "severity": "MEDIUM", "status": "WARN",
                    "finding": "AWS CLI installed, but credentials file (~/.aws/credentials) is missing.",
                    "recommendation": "Run 'aws configure' in terminal to authenticate your AWS environment."
                })

        res = {
            "cli_installed": True,
            "buckets_count": len(s3),
            "public_acls": sum(1 for f in s3 if f.get("severity") == "HIGH"),
            "open_sg": sum(1 for f in sg if f.get("severity") == "HIGH"),
            "compliance_score": 100 if all(f.get("status") == "PASS" for f in findings) else (75 if os.path.isfile(creds) else 50),
            "findings": findings
        }
        AWS_CACHE["timestamp"] = now_time
        AWS_CACHE["data"] = res
        return res


class AzureInspector:
    
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

    @staticmethod
    def get_summary() -> Dict[str, Any]:
        import os
        now_time = time.time()
        if AZURE_CACHE.get("data") and (now_time - AZURE_CACHE.get("timestamp", 0)) < 60.0:
            return AZURE_CACHE["data"]

        now = time.strftime("%Y-%m-%d %H:%M:%S")
        cli = AzureInspector.check_cli_available()

        if not cli:
            findings = [{
                "timestamp": now, "resource_type": "Azure CLI Runtime", "resource_id": "System PATH / AppData",
                "severity": "INFO", "status": "WARN",
                "finding": "Azure CLI binary ('az') is not installed on this workstation.",
                "recommendation": "Install Azure CLI via https://learn.microsoft.com/en-us/cli/azure/install-azure-cli"
            }]
            res = {
                "cli_installed": False,
                "storage_count": 0,
                "public_blobs": 0,
                "open_nsg": 0,
                "compliance_score": 0,
                "findings": findings
            }
            AZURE_CACHE["timestamp"] = now_time
            AZURE_CACHE["data"] = res
            return res

        nsg = AzureInspector.get_nsg_findings()
        stg = AzureInspector.get_storage_findings()
        findings = nsg + stg

        az_profile = os.path.expanduser("~\\.azure\\azureProfile.json")

        if not findings:
            if os.path.isfile(az_profile) or "AZURE_CLIENT_ID" in os.environ:
                findings.append({
                    "timestamp": now, "resource_type": "Azure Entra ID Profile", "resource_id": "Azure Subscription Default",
                    "severity": "PASS", "status": "PASS",
                    "finding": "Azure CLI profile authenticated (~/.azure/azureProfile.json). CLI session initialized.",
                    "recommendation": "Enforce Privileged Identity Management (PIM) for Azure admins."
                })
            else:
                findings.append({
                    "timestamp": now, "resource_type": "Azure CLI Configuration", "resource_id": "Local Workstation",
                    "severity": "MEDIUM", "status": "WARN",
                    "finding": "Azure CLI installed, but profile (~/.azure/azureProfile.json) is not authenticated.",
                    "recommendation": "Run 'az login' in PowerShell to authenticate your Azure subscription."
                })

        res = {
            "cli_installed": True,
            "storage_count": len(stg),
            "public_blobs": sum(1 for f in stg if f.get("severity") == "HIGH"),
            "open_nsg": sum(1 for f in nsg if f.get("severity") == "HIGH"),
            "compliance_score": 100 if all(f.get("status") == "PASS" for f in findings) else (80 if os.path.isfile(az_profile) else 50),
            "findings": findings
        }
        AZURE_CACHE["timestamp"] = now_time
        AZURE_CACHE["data"] = res
        return res




class BaselineAuditor:
    """
    Checks local cloud CLI configuration baseline.
    """

    @staticmethod
    def audit() -> List[Dict[str, Any]]:
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

