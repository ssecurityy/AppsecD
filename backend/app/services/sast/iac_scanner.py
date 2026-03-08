"""IaC (Infrastructure as Code) misconfiguration scanner.

Detects security issues in Terraform, Kubernetes manifests, Dockerfiles,
CloudFormation templates, Helm charts, and Ansible playbooks using
regex-based pattern matching.  150+ rules covering encryption, logging,
access control, container hardening, and cloud best-practices.
"""
import hashlib
import logging
import os
import re
from pathlib import Path

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Binary / skip heuristics
# ---------------------------------------------------------------------------
SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2",
    ".ttf", ".eot", ".pdf", ".zip", ".tar", ".gz", ".bz2", ".xz",
    ".bin", ".exe", ".dll", ".so", ".dylib", ".pyc", ".pyo",
    ".lock", ".sum", ".map", ".min.js",
}

SKIP_DIRS = {
    "node_modules", ".git", "vendor", "__pycache__", "dist", "build",
    ".next", ".terraform", ".terragrunt-cache",
}

MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB


# ═══════════════════════════════════════════════════════════════════════════
# Fingerprint helper
# ═══════════════════════════════════════════════════════════════════════════
def _fingerprint(rule_id: str, file_path: str, line: int) -> str:
    """SHA-256 fingerprint for dedup (first 32 hex chars)."""
    raw = f"{rule_id}|{file_path}|{line}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


# ═══════════════════════════════════════════════════════════════════════════
# File-type detection
# ═══════════════════════════════════════════════════════════════════════════
def _is_terraform(path: str, _content: str | None = None) -> bool:
    return path.endswith(".tf") or path.endswith(".tfvars")


def _is_kubernetes(path: str, content: str) -> bool:
    if not (path.endswith(".yaml") or path.endswith(".yml")):
        return False
    return bool(re.search(
        r"^\s*kind\s*:\s*(Deployment|Pod|StatefulSet|DaemonSet|ReplicaSet|Job|CronJob|Service)\b",
        content, re.MULTILINE,
    ))


def _is_dockerfile(path: str, _content: str | None = None) -> bool:
    basename = os.path.basename(path)
    return basename == "Dockerfile" or basename.startswith("Dockerfile.")


def _is_cloudformation(path: str, content: str) -> bool:
    if not (path.endswith(".yaml") or path.endswith(".yml") or path.endswith(".json")):
        return False
    return "AWSTemplateFormatVersion" in content


def _is_helm_values(path: str, _content: str | None = None) -> bool:
    basename = os.path.basename(path)
    # values.yaml sitting alongside Chart.yaml
    if basename in ("values.yaml", "values.yml"):
        chart_file = os.path.join(os.path.dirname(path), "Chart.yaml")
        if os.path.isfile(chart_file):
            return True
    return False


def _is_ansible(path: str, content: str) -> bool:
    if not (path.endswith(".yaml") or path.endswith(".yml")):
        return False
    basename = os.path.basename(path)
    # Common ansible file patterns
    if basename in ("playbook.yml", "playbook.yaml", "site.yml", "site.yaml"):
        return True
    # Files inside roles/, tasks/, handlers/ directories
    parts = Path(path).parts
    if any(p in ("tasks", "handlers", "roles", "playbooks") for p in parts):
        return True
    # Heuristic: contains ansible task-like structures
    return bool(re.search(r"^\s*-\s+(name|hosts|tasks|roles)\s*:", content, re.MULTILINE))


# ═══════════════════════════════════════════════════════════════════════════
# Terraform block extraction helper
# ═══════════════════════════════════════════════════════════════════════════
def _extract_tf_block(full_text: str, start: int) -> str:
    """Extract a brace-delimited Terraform resource block starting from *start*."""
    brace_depth = 0
    block_end = start
    for i in range(start, len(full_text)):
        if full_text[i] == "{":
            brace_depth += 1
        elif full_text[i] == "}":
            brace_depth -= 1
            if brace_depth == 0:
                block_end = i
                break
    return full_text[start:block_end + 1]


# ═══════════════════════════════════════════════════════════════════════════
# Terraform checks
# ═══════════════════════════════════════════════════════════════════════════
def _scan_terraform(lines: list[str], rel_path: str) -> list[dict]:
    findings: list[dict] = []
    full_text = "".join(lines)

    checks: list[tuple[str, str, str, str, str, str, str]] = [
        # (regex, rule_id, severity, confidence, title, description, cwe)
    ]

    # --- Public S3 bucket ---
    for m in re.finditer(r'acl\s*=\s*"(public-read|public-read-write)"', full_text):
        ln = full_text[:m.start()].count("\n") + 1
        findings.append(_tf_finding(
            "iac.terraform.public-s3-bucket", "high", "high",
            "S3 bucket configured with public access",
            f"The S3 bucket ACL is set to '{m.group(1)}', making objects publicly accessible. "
            "Use private ACL and S3 bucket policies with least-privilege access instead.",
            rel_path, ln, m.group(0), "CWE-284", "A01:2021",
        ))

    # --- Unencrypted S3 (missing server_side_encryption_configuration) ---
    for m in re.finditer(r'resource\s+"aws_s3_bucket"\s+"([^"]+)"', full_text):
        block_start = m.start()
        # Find the closing brace of the resource block
        brace_depth = 0
        block_end = block_start
        for i in range(m.end(), len(full_text)):
            if full_text[i] == "{":
                brace_depth += 1
            elif full_text[i] == "}":
                brace_depth -= 1
                if brace_depth == 0:
                    block_end = i
                    break
        block = full_text[block_start:block_end]
        if "encryption_configuration" not in block and "server_side_encryption" not in block:
            ln = full_text[:block_start].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.unencrypted-s3", "high", "medium",
                f"S3 bucket '{m.group(1)}' missing encryption configuration",
                "S3 bucket does not have server-side encryption configured. Enable SSE-S3 or SSE-KMS "
                "to protect data at rest.",
                rel_path, ln, m.group(0), "CWE-311", "A02:2021",
            ))

    # --- Overly permissive IAM ---
    for m in re.finditer(
        r'(?s)effect\s*=\s*"Allow".*?actions?\s*=\s*\[\s*"\*"\s*\].*?resources?\s*=\s*\[\s*"\*"\s*\]',
        full_text, re.IGNORECASE,
    ):
        ln = full_text[:m.start()].count("\n") + 1
        findings.append(_tf_finding(
            "iac.terraform.overly-permissive-iam", "critical", "high",
            "IAM policy grants full access (Action: *, Resource: *)",
            "The IAM policy allows all actions on all resources. Apply least-privilege by scoping "
            "actions and resources to only what is required.",
            rel_path, ln, m.group(0)[:200], "CWE-250", "A01:2021",
        ))

    # Also check the reverse order (resources before actions)
    for m in re.finditer(
        r'(?s)effect\s*=\s*"Allow".*?resources?\s*=\s*\[\s*"\*"\s*\].*?actions?\s*=\s*\[\s*"\*"\s*\]',
        full_text, re.IGNORECASE,
    ):
        ln = full_text[:m.start()].count("\n") + 1
        fp = _fingerprint("iac.terraform.overly-permissive-iam", rel_path, ln)
        # Avoid duplicate if already found
        if not any(f["fingerprint"] == fp for f in findings):
            findings.append(_tf_finding(
                "iac.terraform.overly-permissive-iam", "critical", "high",
                "IAM policy grants full access (Action: *, Resource: *)",
                "The IAM policy allows all actions on all resources. Apply least-privilege by scoping "
                "actions and resources to only what is required.",
                rel_path, ln, m.group(0)[:200], "CWE-250", "A01:2021",
            ))

    # --- Security group 0.0.0.0/0 ingress ---
    for m in re.finditer(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]', full_text):
        ln = full_text[:m.start()].count("\n") + 1
        # Check if this is within an ingress block
        context_start = max(0, m.start() - 300)
        context = full_text[context_start:m.start()]
        if "ingress" in context or "inbound" in context.lower():
            findings.append(_tf_finding(
                "iac.terraform.open-security-group", "high", "high",
                "Security group allows ingress from 0.0.0.0/0",
                "Security group rule allows inbound traffic from any IP address. Restrict ingress "
                "to specific CIDR ranges that require access.",
                rel_path, ln, m.group(0), "CWE-284", "A01:2021",
            ))

    # --- Also catch standalone open CIDR even without obvious ingress context ---
    for m in re.finditer(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]', full_text):
        ln = full_text[:m.start()].count("\n") + 1
        fp = _fingerprint("iac.terraform.open-cidr-block", rel_path, ln)
        if not any(f["fingerprint"] == fp for f in findings):
            context_start = max(0, m.start() - 300)
            context = full_text[context_start:m.start()]
            if "ingress" not in context and "inbound" not in context.lower():
                findings.append(_tf_finding(
                    "iac.terraform.open-cidr-block", "medium", "medium",
                    "Network rule references 0.0.0.0/0 (open to all)",
                    "A network rule uses 0.0.0.0/0 which may expose resources to the internet. "
                    "Verify this is intentional and restrict where possible.",
                    rel_path, ln, m.group(0), "CWE-284", "A01:2021",
                ))

    # --- Missing logging / CloudTrail ---
    if re.search(r'resource\s+"aws_', full_text) and not re.search(
        r'(aws_cloudtrail|aws_flow_log|logging|access_logs|aws_s3_bucket_logging)', full_text
    ):
        findings.append(_tf_finding(
            "iac.terraform.missing-logging", "medium", "low",
            "No logging or monitoring resources defined",
            "The Terraform configuration does not include CloudTrail, VPC flow logs, or S3 access "
            "logging. Enable logging to maintain an audit trail.",
            rel_path, 1, "", "CWE-778", "A09:2021",
        ))

    # --- Unencrypted RDS ---
    for m in re.finditer(r'resource\s+"aws_db_instance"\s+"([^"]+)"', full_text):
        block_start = m.start()
        brace_depth = 0
        block_end = block_start
        for i in range(m.end(), len(full_text)):
            if full_text[i] == "{":
                brace_depth += 1
            elif full_text[i] == "}":
                brace_depth -= 1
                if brace_depth == 0:
                    block_end = i
                    break
        block = full_text[block_start:block_end]
        if "storage_encrypted" not in block or re.search(r"storage_encrypted\s*=\s*false", block):
            ln = full_text[:block_start].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.unencrypted-rds", "high", "high",
                f"RDS instance '{m.group(1)}' does not have storage encryption enabled",
                "RDS storage encryption is not enabled. Set storage_encrypted = true to encrypt "
                "data at rest using KMS.",
                rel_path, ln, m.group(0), "CWE-311", "A02:2021",
            ))

    # --- Public RDS ---
    for m in re.finditer(r"publicly_accessible\s*=\s*true", full_text):
        ln = full_text[:m.start()].count("\n") + 1
        findings.append(_tf_finding(
            "iac.terraform.public-rds", "critical", "high",
            "RDS instance is publicly accessible",
            "The RDS instance has publicly_accessible set to true, exposing the database to the "
            "internet. Set publicly_accessible = false and use private subnets.",
            rel_path, ln, m.group(0), "CWE-284", "A01:2021",
        ))

    # --- Missing VPC flow logs ---
    if re.search(r'resource\s+"aws_vpc"', full_text) and not re.search(
        r'resource\s+"aws_flow_log"', full_text
    ):
        findings.append(_tf_finding(
            "iac.terraform.missing-vpc-flow-logs", "medium", "medium",
            "VPC defined without flow logs",
            "A VPC resource is defined but no aws_flow_log resource exists. Enable VPC flow logs "
            "to capture network traffic metadata for security monitoring.",
            rel_path, 1, "", "CWE-778", "A09:2021",
        ))

    # --- EBS encryption ---
    for m in re.finditer(r'resource\s+"aws_ebs_volume"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if "encrypted" not in block or re.search(r"encrypted\s*=\s*false", block):
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.unencrypted-ebs", "high", "high",
                f"EBS volume '{m.group(1)}' missing encryption",
                "EBS volume does not have encryption enabled. Set encrypted = true to "
                "protect data at rest.",
                rel_path, ln, m.group(0), "CWE-311", "A02:2021",
            ))

    # --- EFS encryption ---
    for m in re.finditer(r'resource\s+"aws_efs_file_system"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if "encrypted" not in block or re.search(r"encrypted\s*=\s*false", block):
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.unencrypted-efs", "high", "high",
                f"EFS file system '{m.group(1)}' missing encryption",
                "EFS file system does not have encryption enabled. Set encrypted = true.",
                rel_path, ln, m.group(0), "CWE-311", "A02:2021",
            ))

    # --- ElastiCache encryption ---
    for m in re.finditer(r'resource\s+"aws_elasticache_replication_group"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        ln = full_text[:m.start()].count("\n") + 1
        if "transit_encryption_enabled" not in block or re.search(r"transit_encryption_enabled\s*=\s*false", block):
            findings.append(_tf_finding(
                "iac.terraform.elasticache-no-transit-encryption", "high", "high",
                f"ElastiCache replication group '{m.group(1)}' missing transit encryption",
                "ElastiCache does not have transit encryption enabled. Set "
                "transit_encryption_enabled = true to encrypt data in transit.",
                rel_path, ln, m.group(0), "CWE-319", "A02:2021",
            ))
        if "at_rest_encryption_enabled" not in block or re.search(r"at_rest_encryption_enabled\s*=\s*false", block):
            findings.append(_tf_finding(
                "iac.terraform.elasticache-no-rest-encryption", "high", "high",
                f"ElastiCache replication group '{m.group(1)}' missing at-rest encryption",
                "ElastiCache does not have at-rest encryption enabled. Set "
                "at_rest_encryption_enabled = true.",
                rel_path, ln, m.group(0), "CWE-311", "A02:2021",
            ))

    # --- Redshift encryption ---
    for m in re.finditer(r'resource\s+"aws_redshift_cluster"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if "encrypted" not in block or re.search(r"encrypted\s*=\s*false", block):
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.unencrypted-redshift", "high", "high",
                f"Redshift cluster '{m.group(1)}' missing encryption",
                "Redshift cluster does not have encryption enabled. Set encrypted = true.",
                rel_path, ln, m.group(0), "CWE-311", "A02:2021",
            ))

    # --- SNS encryption ---
    for m in re.finditer(r'resource\s+"aws_sns_topic"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if "kms_master_key_id" not in block:
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.unencrypted-sns", "medium", "high",
                f"SNS topic '{m.group(1)}' missing KMS encryption",
                "SNS topic does not have KMS encryption configured. Set kms_master_key_id "
                "to encrypt messages at rest.",
                rel_path, ln, m.group(0), "CWE-311", "A02:2021",
            ))

    # --- SQS encryption ---
    for m in re.finditer(r'resource\s+"aws_sqs_queue"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if "kms_master_key_id" not in block:
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.unencrypted-sqs", "medium", "high",
                f"SQS queue '{m.group(1)}' missing KMS encryption",
                "SQS queue does not have KMS encryption configured. Set kms_master_key_id "
                "to encrypt messages at rest.",
                rel_path, ln, m.group(0), "CWE-311", "A02:2021",
            ))

    # --- KMS key rotation ---
    for m in re.finditer(r'resource\s+"aws_kms_key"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if "enable_key_rotation" not in block or re.search(r"enable_key_rotation\s*=\s*false", block):
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.kms-key-rotation-disabled", "medium", "high",
                f"KMS key '{m.group(1)}' does not have key rotation enabled",
                "KMS key does not have automatic key rotation enabled. Set "
                "enable_key_rotation = true to rotate keys annually.",
                rel_path, ln, m.group(0), "CWE-320", "A02:2021",
            ))

    # --- CloudWatch log retention ---
    for m in re.finditer(r'resource\s+"aws_cloudwatch_log_group"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if "retention_in_days" not in block or re.search(r"retention_in_days\s*=\s*0\b", block):
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.cloudwatch-log-no-retention", "medium", "medium",
                f"CloudWatch log group '{m.group(1)}' has no retention policy",
                "CloudWatch log group does not set retention_in_days or sets it to 0 "
                "(infinite). Set an appropriate retention period to manage costs and compliance.",
                rel_path, ln, m.group(0), "CWE-779", "A09:2021",
            ))

    # --- CloudTrail multi-region ---
    for m in re.finditer(r'resource\s+"aws_cloudtrail"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if "is_multi_region_trail" not in block or re.search(r"is_multi_region_trail\s*=\s*false", block):
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.cloudtrail-not-multi-region", "medium", "high",
                f"CloudTrail '{m.group(1)}' is not multi-region",
                "CloudTrail is not configured as a multi-region trail. Set "
                "is_multi_region_trail = true to capture events in all regions.",
                rel_path, ln, m.group(0), "CWE-778", "A09:2021",
            ))

    # --- CloudTrail log validation ---
    for m in re.finditer(r'resource\s+"aws_cloudtrail"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if "enable_log_file_validation" not in block or re.search(r"enable_log_file_validation\s*=\s*false", block):
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.cloudtrail-no-log-validation", "medium", "high",
                f"CloudTrail '{m.group(1)}' missing log file validation",
                "CloudTrail does not have log file validation enabled. Set "
                "enable_log_file_validation = true to detect log tampering.",
                rel_path, ln, m.group(0), "CWE-354", "A09:2021",
            ))

    # --- Lambda reserved concurrency ---
    for m in re.finditer(r'resource\s+"aws_lambda_function"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if "reserved_concurrent_executions" not in block:
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.lambda-no-reserved-concurrency", "low", "medium",
                f"Lambda function '{m.group(1)}' has no reserved concurrency limit",
                "Lambda function does not set reserved_concurrent_executions. Without a "
                "limit, the function can consume the entire account concurrency pool.",
                rel_path, ln, m.group(0), "CWE-770", "A05:2021",
            ))

    # --- API Gateway logging ---
    for m in re.finditer(r'resource\s+"aws_api_gateway_stage"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if "access_log_settings" not in block:
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.apigw-no-access-logging", "medium", "high",
                f"API Gateway stage '{m.group(1)}' missing access logging",
                "API Gateway stage does not have access_log_settings configured. Enable "
                "access logging to capture request metadata for monitoring.",
                rel_path, ln, m.group(0), "CWE-778", "A09:2021",
            ))

    # --- API Gateway WAF ---
    if re.search(r'resource\s+"aws_api_gateway_rest_api"', full_text) and not re.search(
        r'resource\s+"aws_wafv2_web_acl_association"', full_text
    ) and not re.search(r'resource\s+"aws_waf_web_acl"', full_text):
        findings.append(_tf_finding(
            "iac.terraform.apigw-no-waf", "medium", "medium",
            "API Gateway REST API defined without WAF association",
            "An API Gateway REST API is defined but no WAF association resource exists. "
            "Attach a WAF WebACL to protect against common web attacks.",
            rel_path, 1, "", "CWE-693", "A05:2021",
        ))

    # --- S3 versioning ---
    for m in re.finditer(r'resource\s+"aws_s3_bucket"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if "versioning" not in block or not re.search(r"versioning\s*\{[^}]*enabled\s*=\s*true", block, re.DOTALL):
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.s3-no-versioning", "medium", "medium",
                f"S3 bucket '{m.group(1)}' does not have versioning enabled",
                "S3 bucket versioning is not enabled. Enable versioning to protect "
                "against accidental deletion and support recovery.",
                rel_path, ln, m.group(0), "CWE-693", "A05:2021",
            ))

    # --- S3 MFA delete ---
    for m in re.finditer(r'resource\s+"aws_s3_bucket"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if "versioning" in block and "mfa_delete" not in block:
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.s3-no-mfa-delete", "medium", "medium",
                f"S3 bucket '{m.group(1)}' versioning without MFA delete",
                "S3 bucket has versioning but MFA delete is not enabled. Enable "
                "mfa_delete = true to require MFA for object deletion.",
                rel_path, ln, m.group(0), "CWE-308", "A07:2021",
            ))

    # --- S3 public access block ---
    for m in re.finditer(r'resource\s+"aws_s3_bucket"\s+"([^"]+)"', full_text):
        bucket_name = m.group(1)
        if not re.search(
            rf'resource\s+"aws_s3_bucket_public_access_block"\s+"[^"]*".*?bucket\s*=\s*aws_s3_bucket\.{re.escape(bucket_name)}',
            full_text, re.DOTALL,
        ) and "aws_s3_bucket_public_access_block" not in full_text:
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.s3-no-public-access-block", "high", "medium",
                f"S3 bucket '{bucket_name}' missing public access block",
                "No aws_s3_bucket_public_access_block resource is defined. Add a public "
                "access block to prevent accidental public exposure.",
                rel_path, ln, m.group(0), "CWE-284", "A01:2021",
            ))

    # --- RDS auto minor version upgrade ---
    for m in re.finditer(r'resource\s+"aws_db_instance"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if re.search(r"auto_minor_version_upgrade\s*=\s*false", block):
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.rds-no-auto-minor-upgrade", "low", "high",
                f"RDS instance '{m.group(1)}' has auto minor version upgrade disabled",
                "RDS auto_minor_version_upgrade is set to false. Enable it to receive "
                "automatic security patches.",
                rel_path, ln, m.group(0), "CWE-1104", "A06:2021",
            ))

    # --- ALB access logging ---
    for m in re.finditer(r'resource\s+"aws_lb"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if "access_logs" not in block or not re.search(r"access_logs\s*\{[^}]*enabled\s*=\s*true", block, re.DOTALL):
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.alb-no-access-logs", "medium", "high",
                f"Load balancer '{m.group(1)}' missing access logging",
                "ALB/NLB does not have access logs enabled. Enable access_logs with "
                "enabled = true to capture request metadata.",
                rel_path, ln, m.group(0), "CWE-778", "A09:2021",
            ))

    # --- DynamoDB PITR ---
    for m in re.finditer(r'resource\s+"aws_dynamodb_table"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if "point_in_time_recovery" not in block or not re.search(
            r"point_in_time_recovery\s*\{[^}]*enabled\s*=\s*true", block, re.DOTALL
        ):
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.dynamodb-no-pitr", "medium", "high",
                f"DynamoDB table '{m.group(1)}' missing point-in-time recovery",
                "DynamoDB table does not have point_in_time_recovery enabled. Enable "
                "PITR to support continuous backups and recovery.",
                rel_path, ln, m.group(0), "CWE-693", "A05:2021",
            ))

    # --- DynamoDB encryption ---
    for m in re.finditer(r'resource\s+"aws_dynamodb_table"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if "server_side_encryption" not in block or not re.search(
            r"server_side_encryption\s*\{[^}]*enabled\s*=\s*true", block, re.DOTALL
        ):
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.dynamodb-no-encryption", "high", "high",
                f"DynamoDB table '{m.group(1)}' missing server-side encryption",
                "DynamoDB table does not have server_side_encryption enabled. Enable SSE "
                "with a KMS key to protect data at rest.",
                rel_path, ln, m.group(0), "CWE-311", "A02:2021",
            ))

    # --- ECR image scanning ---
    for m in re.finditer(r'resource\s+"aws_ecr_repository"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if "image_scanning_configuration" not in block or not re.search(
            r"image_scanning_configuration\s*\{[^}]*scan_on_push\s*=\s*true", block, re.DOTALL
        ):
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.ecr-no-image-scanning", "medium", "high",
                f"ECR repository '{m.group(1)}' missing image scanning on push",
                "ECR repository does not have scan_on_push enabled. Enable "
                "image_scanning_configuration to detect vulnerabilities in pushed images.",
                rel_path, ln, m.group(0), "CWE-693", "A06:2021",
            ))

    # --- ECR immutable tags ---
    for m in re.finditer(r'resource\s+"aws_ecr_repository"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if "IMMUTABLE" not in block:
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.ecr-mutable-tags", "medium", "high",
                f"ECR repository '{m.group(1)}' allows mutable image tags",
                "ECR repository does not set image_tag_mutability to IMMUTABLE. Mutable "
                "tags allow overwriting images. Set image_tag_mutability = \"IMMUTABLE\".",
                rel_path, ln, m.group(0), "CWE-345", "A08:2021",
            ))

    # --- GuardDuty enabled ---
    for m in re.finditer(r'resource\s+"aws_guardduty_detector"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if re.search(r"enable\s*=\s*false", block):
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.guardduty-disabled", "high", "high",
                f"GuardDuty detector '{m.group(1)}' is disabled",
                "GuardDuty detector has enable = false. GuardDuty provides threat "
                "detection. Set enable = true.",
                rel_path, ln, m.group(0), "CWE-778", "A09:2021",
            ))

    # --- Config recorder ---
    if re.search(r'resource\s+"aws_', full_text) and not re.search(
        r'resource\s+"aws_config_configuration_recorder"', full_text
    ) and not re.search(r"aws_config", full_text):
        # Only flag if there are AWS resources but no config recorder at all
        pass  # This is a file-level heuristic, keep low noise

    # --- SSM Session Manager encryption ---
    for m in re.finditer(r'resource\s+"aws_ssm_document"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if "kms" not in block.lower() and "encrypt" not in block.lower():
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.ssm-no-encryption", "medium", "medium",
                f"SSM document '{m.group(1)}' missing encryption configuration",
                "SSM document does not reference KMS encryption. Configure KMS encryption "
                "for Session Manager sessions.",
                rel_path, ln, m.group(0), "CWE-311", "A02:2021",
            ))

    # --- ElasticSearch encryption at rest ---
    for m in re.finditer(r'resource\s+"aws_elasticsearch_domain"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if "encrypt_at_rest" not in block:
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.elasticsearch-no-encryption", "high", "high",
                f"ElasticSearch domain '{m.group(1)}' missing encrypt_at_rest",
                "ElasticSearch domain does not have encrypt_at_rest configured. Enable "
                "encryption at rest to protect stored data.",
                rel_path, ln, m.group(0), "CWE-311", "A02:2021",
            ))

    # --- ElasticSearch node-to-node encryption ---
    for m in re.finditer(r'resource\s+"aws_elasticsearch_domain"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if "node_to_node_encryption" not in block:
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.elasticsearch-no-node-encryption", "high", "high",
                f"ElasticSearch domain '{m.group(1)}' missing node-to-node encryption",
                "ElasticSearch domain does not have node_to_node_encryption configured. "
                "Enable it to encrypt inter-node traffic.",
                rel_path, ln, m.group(0), "CWE-319", "A02:2021",
            ))

    # --- WAF rules ---
    for m in re.finditer(r'resource\s+"aws_wafv2_web_acl"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        if "rule" not in block:
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_tf_finding(
                "iac.terraform.waf-no-rules", "high", "high",
                f"WAFv2 WebACL '{m.group(1)}' has no rules defined",
                "WAFv2 WebACL is defined without any rules. Add rules to filter malicious "
                "traffic (e.g. AWS managed rule groups).",
                rel_path, ln, m.group(0), "CWE-693", "A05:2021",
            ))

    # --- IAM password policy ---
    for m in re.finditer(r'resource\s+"aws_iam_account_password_policy"\s+"([^"]+)"', full_text):
        block = _extract_tf_block(full_text, m.start())
        ln = full_text[:m.start()].count("\n") + 1
        if re.search(r"minimum_password_length\s*=\s*(\d+)", block):
            length_m = re.search(r"minimum_password_length\s*=\s*(\d+)", block)
            if length_m and int(length_m.group(1)) < 14:
                findings.append(_tf_finding(
                    "iac.terraform.weak-password-policy-length", "medium", "high",
                    f"IAM password policy '{m.group(1)}' minimum length below 14",
                    f"IAM password policy sets minimum_password_length to "
                    f"{length_m.group(1)}. CIS recommends at least 14 characters.",
                    rel_path, ln, length_m.group(0), "CWE-521", "A07:2021",
                ))
        if re.search(r"require_uppercase_characters\s*=\s*false", block):
            findings.append(_tf_finding(
                "iac.terraform.weak-password-policy-uppercase", "low", "high",
                f"IAM password policy '{m.group(1)}' does not require uppercase",
                "IAM password policy does not require uppercase characters. Enable "
                "require_uppercase_characters = true.",
                rel_path, ln, m.group(0), "CWE-521", "A07:2021",
            ))
        if re.search(r"max_password_age\s*=\s*0\b", block) or "max_password_age" not in block:
            findings.append(_tf_finding(
                "iac.terraform.password-policy-no-expiry", "low", "medium",
                f"IAM password policy '{m.group(1)}' has no password expiry",
                "IAM password policy does not enforce password expiry. Set max_password_age "
                "to an appropriate value (e.g. 90 days).",
                rel_path, ln, m.group(0), "CWE-521", "A07:2021",
            ))

    return findings


def _tf_finding(
    rule_id: str, severity: str, confidence: str,
    title: str, description: str,
    file_path: str, line: int, snippet: str,
    cwe_id: str, owasp: str,
) -> dict:
    return {
        "rule_id": rule_id,
        "rule_source": "iac",
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "description": description,
        "file_path": file_path,
        "line_start": line,
        "line_end": line,
        "code_snippet": snippet[:2000],
        "cwe_id": cwe_id,
        "owasp_category": owasp,
        "fingerprint": _fingerprint(rule_id, file_path, line),
    }


# ═══════════════════════════════════════════════════════════════════════════
# Kubernetes checks
# ═══════════════════════════════════════════════════════════════════════════
def _scan_kubernetes(lines: list[str], rel_path: str) -> list[dict]:
    findings: list[dict] = []
    full_text = "".join(lines)

    # --- Privileged container ---
    for m in re.finditer(r"privileged\s*:\s*true", full_text):
        ln = full_text[:m.start()].count("\n") + 1
        findings.append(_k8s_finding(
            "iac.kubernetes.privileged-container", "critical", "high",
            "Container running in privileged mode",
            "A container is configured with securityContext.privileged: true, granting full host "
            "access. Remove the privileged flag or set it to false.",
            rel_path, ln, m.group(0), "CWE-250", "A01:2021",
        ))

    # --- Running as root (runAsUser: 0) ---
    for m in re.finditer(r"runAsUser\s*:\s*0\b", full_text):
        ln = full_text[:m.start()].count("\n") + 1
        findings.append(_k8s_finding(
            "iac.kubernetes.run-as-root", "high", "high",
            "Container configured to run as root (UID 0)",
            "The container is set to run as root user. Use a non-root user by setting "
            "runAsUser to a non-zero value and runAsNonRoot: true.",
            rel_path, ln, m.group(0), "CWE-250", "A01:2021",
        ))

    # --- Missing runAsNonRoot ---
    if re.search(r"kind\s*:\s*(Deployment|Pod|StatefulSet|DaemonSet)", full_text):
        if not re.search(r"runAsNonRoot\s*:\s*true", full_text):
            findings.append(_k8s_finding(
                "iac.kubernetes.missing-run-as-non-root", "medium", "medium",
                "Container does not enforce non-root execution",
                "The manifest does not set runAsNonRoot: true. Without this, containers may run "
                "as root by default. Add securityContext.runAsNonRoot: true.",
                rel_path, 1, "", "CWE-250", "A01:2021",
            ))

    # --- Missing resource limits ---
    if re.search(r"kind\s*:\s*(Deployment|Pod|StatefulSet|DaemonSet)", full_text):
        if not re.search(r"resources\s*:.*limits\s*:", full_text, re.DOTALL):
            findings.append(_k8s_finding(
                "iac.kubernetes.missing-resource-limits", "medium", "medium",
                "Container missing resource limits",
                "No resource limits (CPU/memory) are defined. Without limits a container can "
                "consume all node resources, affecting other workloads. Add resources.limits.",
                rel_path, 1, "", "CWE-770", "A05:2021",
            ))

    # --- hostPath volume ---
    for m in re.finditer(r"hostPath\s*:", full_text):
        ln = full_text[:m.start()].count("\n") + 1
        findings.append(_k8s_finding(
            "iac.kubernetes.hostpath-volume", "high", "high",
            "Volume uses hostPath mount",
            "hostPath volumes mount host filesystem directories into pods, which can lead to "
            "container escapes. Use persistent volume claims or other storage drivers instead.",
            rel_path, ln, m.group(0), "CWE-284", "A01:2021",
        ))

    # --- Missing network policies ---
    # Only flag if it is a Deployment/Pod, not a NetworkPolicy itself
    kind_match = re.search(r"kind\s*:\s*(Deployment|Pod|StatefulSet|DaemonSet)", full_text)
    if kind_match and "NetworkPolicy" not in full_text:
        findings.append(_k8s_finding(
            "iac.kubernetes.missing-network-policy", "medium", "low",
            "No NetworkPolicy defined alongside workload",
            "The manifest defines a workload but no NetworkPolicy. Without network policies, pods "
            "can communicate freely. Define NetworkPolicy resources for network segmentation.",
            rel_path, 1, "", "CWE-284", "A01:2021",
        ))

    # --- Default namespace ---
    ns_match = re.search(r"namespace\s*:\s*['\"]?default['\"]?", full_text)
    if ns_match:
        ln = full_text[:ns_match.start()].count("\n") + 1
        findings.append(_k8s_finding(
            "iac.kubernetes.default-namespace", "low", "high",
            "Workload deployed to the default namespace",
            "Using the default namespace reduces isolation between workloads. Deploy to a "
            "dedicated namespace with appropriate RBAC and resource quotas.",
            rel_path, ln, ns_match.group(0), "CWE-284", "A01:2021",
        ))
    elif kind_match and not re.search(r"namespace\s*:", full_text):
        # No namespace specified at all -> defaults to 'default'
        findings.append(_k8s_finding(
            "iac.kubernetes.default-namespace", "low", "medium",
            "Workload has no namespace specified (defaults to 'default')",
            "No namespace is specified so Kubernetes will use the default namespace. "
            "Specify a dedicated namespace for better isolation.",
            rel_path, 1, "", "CWE-284", "A01:2021",
        ))

    # --- hostNetwork ---
    for m in re.finditer(r"hostNetwork\s*:\s*true", full_text):
        ln = full_text[:m.start()].count("\n") + 1
        findings.append(_k8s_finding(
            "iac.kubernetes.host-network", "high", "high",
            "Pod uses host network namespace",
            "hostNetwork: true shares the host's network namespace with the pod. This can "
            "expose host services and bypass network policies. Remove unless required.",
            rel_path, ln, m.group(0), "CWE-284", "A01:2021",
        ))

    # --- Missing readiness/liveness probes ---
    if re.search(r"kind\s*:\s*(Deployment|StatefulSet|DaemonSet)", full_text):
        if not re.search(r"(readinessProbe|livenessProbe)\s*:", full_text):
            findings.append(_k8s_finding(
                "iac.kubernetes.missing-probes", "low", "medium",
                "Container missing readiness and liveness probes",
                "No readiness or liveness probes are defined. Without probes, Kubernetes cannot "
                "detect unhealthy containers or avoid routing traffic to unready pods.",
                rel_path, 1, "", "CWE-693", "A05:2021",
            ))

    # --- Writable root filesystem ---
    if re.search(r"kind\s*:\s*(Deployment|Pod|StatefulSet|DaemonSet)", full_text):
        if not re.search(r"readOnlyRootFilesystem\s*:\s*true", full_text):
            findings.append(_k8s_finding(
                "iac.kubernetes.writable-root-fs", "medium", "medium",
                "Container root filesystem is writable",
                "The container does not set readOnlyRootFilesystem: true. A writable root "
                "filesystem allows attackers to modify binaries or install malware. Set "
                "securityContext.readOnlyRootFilesystem: true.",
                rel_path, 1, "", "CWE-284", "A01:2021",
            ))

    # --- allowPrivilegeEscalation ---
    if re.search(r"kind\s*:\s*(Deployment|Pod|StatefulSet|DaemonSet)", full_text):
        if not re.search(r"allowPrivilegeEscalation\s*:\s*false", full_text):
            findings.append(_k8s_finding(
                "iac.kubernetes.allow-privilege-escalation", "high", "medium",
                "Container does not disable privilege escalation",
                "The container does not set allowPrivilegeEscalation: false. This allows "
                "processes to gain more privileges than the parent. Set "
                "securityContext.allowPrivilegeEscalation: false.",
                rel_path, 1, "", "CWE-250", "A01:2021",
            ))

    # --- automountServiceAccountToken ---
    if re.search(r"kind\s*:\s*(Deployment|Pod|StatefulSet|DaemonSet)", full_text):
        if not re.search(r"automountServiceAccountToken\s*:\s*false", full_text):
            findings.append(_k8s_finding(
                "iac.kubernetes.automount-sa-token", "medium", "medium",
                "Pod does not disable automount of service account token",
                "The pod does not set automountServiceAccountToken: false. The mounted "
                "token can be used by attackers for lateral movement. Disable unless needed.",
                rel_path, 1, "", "CWE-284", "A01:2021",
            ))

    # --- imagePullPolicy Always ---
    if re.search(r"kind\s*:\s*(Deployment|Pod|StatefulSet|DaemonSet)", full_text):
        if re.search(r"image\s*:", full_text) and not re.search(r"imagePullPolicy\s*:\s*Always", full_text):
            findings.append(_k8s_finding(
                "iac.kubernetes.image-pull-policy", "low", "medium",
                "Container does not use imagePullPolicy: Always",
                "The container does not set imagePullPolicy: Always. Without this, stale "
                "cached images may be used. Set imagePullPolicy: Always for production.",
                rel_path, 1, "", "CWE-829", "A06:2021",
            ))

    # --- Registry whitelist ---
    for m in re.finditer(r"image\s*:\s*['\"]?(\S+?)['\"]?\s*$", full_text, re.MULTILINE):
        image = m.group(1)
        # Flag images from Docker Hub (no registry prefix) or unknown registries
        if "/" not in image or (not image.startswith(("gcr.io/", "docker.io/", "ghcr.io/",
                "registry.k8s.io/", "quay.io/", "public.ecr.aws/")) and
                "." not in image.split("/")[0]):
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_k8s_finding(
                "iac.kubernetes.unapproved-registry", "low", "low",
                f"Container image '{image}' may not be from an approved registry",
                "The container image does not appear to reference a known registry. "
                "Use images from approved registries to reduce supply-chain risk.",
                rel_path, ln, m.group(0), "CWE-829", "A08:2021",
            ))

    # --- PodDisruptionBudget ---
    # If this file defines a Deployment but no PDB, flag it
    if re.search(r"kind\s*:\s*Deployment", full_text) and not re.search(
        r"kind\s*:\s*PodDisruptionBudget", full_text
    ):
        findings.append(_k8s_finding(
            "iac.kubernetes.missing-pdb", "low", "low",
            "Deployment defined without PodDisruptionBudget",
            "A Deployment is defined but no PodDisruptionBudget exists in the same "
            "manifest. Define a PDB to ensure availability during voluntary disruptions.",
            rel_path, 1, "", "CWE-693", "A05:2021",
        ))

    # --- ResourceQuota ---
    if re.search(r"kind\s*:\s*Namespace", full_text) and not re.search(
        r"kind\s*:\s*ResourceQuota", full_text
    ):
        findings.append(_k8s_finding(
            "iac.kubernetes.missing-resource-quota", "low", "low",
            "Namespace defined without ResourceQuota",
            "A Namespace is defined but no ResourceQuota exists in the same manifest. "
            "Set ResourceQuota to limit resource consumption per namespace.",
            rel_path, 1, "", "CWE-770", "A05:2021",
        ))

    # --- Ingress TLS ---
    if re.search(r"kind\s*:\s*Ingress", full_text):
        if not re.search(r"tls\s*:", full_text):
            findings.append(_k8s_finding(
                "iac.kubernetes.ingress-no-tls", "high", "high",
                "Ingress resource missing TLS configuration",
                "The Ingress does not configure TLS. Without TLS, traffic is unencrypted. "
                "Add a tls section with a valid certificate secret.",
                rel_path, 1, "", "CWE-319", "A02:2021",
            ))

    # --- Secrets in env ---
    for m in re.finditer(r"secretKeyRef\s*:", full_text):
        # Check if it's in an env block (common pattern: env variable from secret)
        context_start = max(0, m.start() - 200)
        context = full_text[context_start:m.start()]
        if "env:" in context or "env :" in context:
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_k8s_finding(
                "iac.kubernetes.secret-in-env", "medium", "medium",
                "Secret referenced in environment variable instead of volume mount",
                "Secrets referenced via secretKeyRef in env are exposed as environment "
                "variables, which may leak in logs. Prefer mounting secrets as files.",
                rel_path, ln, m.group(0), "CWE-200", "A04:2021",
            ))

    # --- RBAC ClusterRoleBinding to cluster-admin ---
    if re.search(r"kind\s*:\s*ClusterRoleBinding", full_text):
        if re.search(r"cluster-admin", full_text):
            findings.append(_k8s_finding(
                "iac.kubernetes.cluster-admin-binding", "critical", "high",
                "ClusterRoleBinding grants cluster-admin role",
                "A ClusterRoleBinding binds to the cluster-admin role which grants "
                "unrestricted cluster access. Use fine-grained roles instead.",
                rel_path, 1, "", "CWE-250", "A01:2021",
            ))

    # --- HostPID ---
    for m in re.finditer(r"hostPID\s*:\s*true", full_text):
        ln = full_text[:m.start()].count("\n") + 1
        findings.append(_k8s_finding(
            "iac.kubernetes.host-pid", "high", "high",
            "Pod uses host PID namespace",
            "hostPID: true shares the host PID namespace with the pod, allowing "
            "processes to see and signal host processes. Remove unless required.",
            rel_path, ln, m.group(0), "CWE-284", "A01:2021",
        ))

    # --- HostIPC ---
    for m in re.finditer(r"hostIPC\s*:\s*true", full_text):
        ln = full_text[:m.start()].count("\n") + 1
        findings.append(_k8s_finding(
            "iac.kubernetes.host-ipc", "high", "high",
            "Pod uses host IPC namespace",
            "hostIPC: true shares the host IPC namespace with the pod, enabling "
            "inter-process communication with host processes. Remove unless required.",
            rel_path, ln, m.group(0), "CWE-284", "A01:2021",
        ))

    # --- Pod security standards (missing securityContext at pod level) ---
    if re.search(r"kind\s*:\s*(Deployment|Pod|StatefulSet|DaemonSet)", full_text):
        # Check for pod-level securityContext (not just container-level)
        spec_match = re.search(r"spec\s*:", full_text)
        if spec_match and not re.search(r"^\s+securityContext\s*:", full_text, re.MULTILINE):
            findings.append(_k8s_finding(
                "iac.kubernetes.missing-pod-security-context", "medium", "medium",
                "Pod missing security context",
                "The pod spec does not include a securityContext. Define pod-level "
                "securityContext with runAsNonRoot, fsGroup, and seccompProfile.",
                rel_path, 1, "", "CWE-250", "A01:2021",
            ))

    # --- Ephemeral storage limits ---
    if re.search(r"kind\s*:\s*(Deployment|Pod|StatefulSet|DaemonSet)", full_text):
        if re.search(r"resources\s*:", full_text) and not re.search(
            r"ephemeral-storage", full_text
        ):
            findings.append(_k8s_finding(
                "iac.kubernetes.no-ephemeral-storage-limit", "low", "low",
                "Container missing ephemeral storage limits",
                "The container defines resource limits but not ephemeral-storage. "
                "Without limits, a pod can exhaust node disk space.",
                rel_path, 1, "", "CWE-770", "A05:2021",
            ))

    # --- Default service account ---
    if re.search(r"kind\s*:\s*(Deployment|Pod|StatefulSet|DaemonSet)", full_text):
        sa_match = re.search(r"serviceAccountName\s*:\s*['\"]?default['\"]?", full_text)
        if sa_match:
            ln = full_text[:sa_match.start()].count("\n") + 1
            findings.append(_k8s_finding(
                "iac.kubernetes.default-service-account", "medium", "high",
                "Pod uses the default service account",
                "The pod uses the 'default' service account. Create a dedicated service "
                "account with minimal RBAC permissions.",
                rel_path, ln, sa_match.group(0), "CWE-284", "A01:2021",
            ))
        elif not re.search(r"serviceAccountName\s*:", full_text):
            findings.append(_k8s_finding(
                "iac.kubernetes.default-service-account", "medium", "medium",
                "Pod does not specify a service account (uses default)",
                "No serviceAccountName is specified so the default service account is "
                "used. Create and assign a dedicated service account.",
                rel_path, 1, "", "CWE-284", "A01:2021",
            ))

    # --- AppArmor profile ---
    if re.search(r"kind\s*:\s*(Deployment|Pod|StatefulSet|DaemonSet)", full_text):
        if not re.search(r"apparmor\.security", full_text) and not re.search(
            r"container\.apparmor\.security\.beta\.kubernetes\.io", full_text
        ):
            findings.append(_k8s_finding(
                "iac.kubernetes.missing-apparmor", "low", "low",
                "Pod missing AppArmor profile annotation",
                "The pod does not have an AppArmor profile annotation. Apply an AppArmor "
                "profile to restrict container capabilities.",
                rel_path, 1, "", "CWE-250", "A01:2021",
            ))

    # --- Seccomp profile ---
    if re.search(r"kind\s*:\s*(Deployment|Pod|StatefulSet|DaemonSet)", full_text):
        if not re.search(r"seccompProfile", full_text) and not re.search(
            r"seccomp\.security", full_text
        ):
            findings.append(_k8s_finding(
                "iac.kubernetes.missing-seccomp", "medium", "medium",
                "Pod missing seccomp profile",
                "The pod does not define a seccompProfile. Apply a seccomp profile "
                "(e.g. RuntimeDefault) to filter dangerous syscalls.",
                rel_path, 1, "", "CWE-250", "A01:2021",
            ))

    return findings


def _k8s_finding(
    rule_id: str, severity: str, confidence: str,
    title: str, description: str,
    file_path: str, line: int, snippet: str,
    cwe_id: str, owasp: str,
) -> dict:
    return {
        "rule_id": rule_id,
        "rule_source": "iac",
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "description": description,
        "file_path": file_path,
        "line_start": line,
        "line_end": line,
        "code_snippet": snippet[:2000],
        "cwe_id": cwe_id,
        "owasp_category": owasp,
        "fingerprint": _fingerprint(rule_id, file_path, line),
    }


# ═══════════════════════════════════════════════════════════════════════════
# Dockerfile checks
# ═══════════════════════════════════════════════════════════════════════════
def _scan_dockerfile(lines: list[str], rel_path: str) -> list[dict]:
    findings: list[dict] = []

    has_user = False
    has_healthcheck = False
    from_count = 0
    has_maintainer = False
    has_apt_or_yum = False
    apt_no_clean_lines: list[int] = []

    for line_num, raw_line in enumerate(lines, 1):
        line = raw_line.strip()

        # Skip comments and blank lines
        if not line or line.startswith("#"):
            continue

        # --- USER instruction ---
        if re.match(r"^USER\s+", line, re.IGNORECASE):
            has_user = True

        # --- HEALTHCHECK ---
        if re.match(r"^HEALTHCHECK\s+", line, re.IGNORECASE):
            has_healthcheck = True

        # --- :latest tag in FROM ---
        m = re.match(r"^FROM\s+(\S+)", line, re.IGNORECASE)
        if m:
            from_count += 1
            image = m.group(1)
            if image.endswith(":latest") or (":" not in image and "@" not in image and image.lower() != "scratch"):
                findings.append(_docker_finding(
                    "iac.dockerfile.latest-tag", "medium", "high",
                    f"FROM uses ':latest' or untagged image: {image}",
                    "Using :latest or an untagged image makes builds non-reproducible. "
                    "Pin to a specific version tag or digest.",
                    rel_path, line_num, line, "CWE-829", "A06:2021",
                ))

        # --- Secrets in ENV ---
        env_match = re.match(
            r"^ENV\s+(\S+)\s*=?\s*(.*)", line, re.IGNORECASE
        )
        if env_match:
            key = env_match.group(1)
            val = env_match.group(2)
            if re.search(
                r"(password|passwd|secret|api_key|apikey|token|private_key|db_pass|auth_token)",
                key, re.IGNORECASE,
            ):
                findings.append(_docker_finding(
                    "iac.dockerfile.secret-in-env", "critical", "high",
                    f"Secret exposed in ENV instruction: {key}",
                    f"The ENV variable '{key}' appears to contain a secret. Use Docker secrets, "
                    "build arguments with --secret, or runtime environment injection instead.",
                    rel_path, line_num, line[:200], "CWE-798", "A07:2021",
                ))

        # --- Secrets in ARG ---
        arg_match = re.match(r"^ARG\s+(\S+?)(?:=(.*))?$", line, re.IGNORECASE)
        if arg_match:
            key = arg_match.group(1)
            if re.search(
                r"(password|passwd|secret|api_key|apikey|token|private_key|db_pass|auth_token)",
                key, re.IGNORECASE,
            ):
                findings.append(_docker_finding(
                    "iac.dockerfile.secret-in-arg", "high", "high",
                    f"Secret exposed in ARG instruction: {key}",
                    f"The ARG '{key}' may contain a secret. ARG values are visible in image "
                    "history. Use Docker BuildKit --secret instead.",
                    rel_path, line_num, line[:200], "CWE-798", "A07:2021",
                ))

        # --- ADD instead of COPY (local files, not URLs or tar auto-extraction) ---
        add_match = re.match(r"^ADD\s+(https?://\S+)", line, re.IGNORECASE)
        if add_match:
            findings.append(_docker_finding(
                "iac.dockerfile.add-instead-of-copy", "medium", "high",
                "ADD used for remote URL instead of COPY",
                "ADD with a URL fetches remote content at build time without checksum verification. "
                "Use RUN curl/wget with checksum validation, or COPY from a prior build stage.",
                rel_path, line_num, line[:200], "CWE-829", "A08:2021",
            ))

        # --- ADD when COPY would suffice (local files, no tar/URL) ---
        add_local = re.match(r"^ADD\s+(?!https?://)(\S+)", line, re.IGNORECASE)
        if add_local:
            src = add_local.group(1)
            if not src.endswith((".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tar.xz")):
                findings.append(_docker_finding(
                    "iac.dockerfile.add-vs-copy", "low", "high",
                    "ADD used when COPY would suffice",
                    "ADD is used for a local file that is not a tar archive. Use COPY for "
                    "simple file copies; ADD should only be used for tar auto-extraction.",
                    rel_path, line_num, line[:200], "CWE-829", "A06:2021",
                ))

        # --- curl piped to sh ---
        if re.search(r"(curl|wget)\s+.*\|\s*(sh|bash|zsh|dash)", line):
            findings.append(_docker_finding(
                "iac.dockerfile.curl-pipe-sh", "high", "high",
                "Remote script piped directly to shell",
                "Fetching a remote script and piping it to a shell is dangerous — it executes "
                "arbitrary code without verification. Download, verify the checksum, then execute.",
                rel_path, line_num, line[:200], "CWE-829", "A08:2021",
            ))

        # --- COPY --chown (informational if not running as root) ---
        copy_match = re.match(r"^COPY\s+", line, re.IGNORECASE)
        if copy_match and has_user and "--chown" not in line:
            findings.append(_docker_finding(
                "iac.dockerfile.copy-no-chown", "low", "medium",
                "COPY without --chown flag after USER instruction",
                "Files are COPYed after a USER instruction but without --chown. The files "
                "will be owned by root. Add --chown=<user>:<group> to set proper ownership.",
                rel_path, line_num, line[:200], "CWE-732", "A01:2021",
            ))

        # --- Package cache cleanup ---
        if re.match(r"^RUN\s+", line, re.IGNORECASE):
            if re.search(r"apt-get\s+install", line) and not re.search(
                r"(rm\s+-rf\s+/var/lib/apt|apt-get\s+clean|--no-install-recommends)", line
            ):
                findings.append(_docker_finding(
                    "iac.dockerfile.apt-no-cleanup", "low", "high",
                    "apt-get install without cache cleanup in same RUN",
                    "apt-get install is used without cleaning the package cache in the same "
                    "RUN instruction. Add '&& rm -rf /var/lib/apt/lists/*' to reduce image size.",
                    rel_path, line_num, line[:200], "CWE-459", "A05:2021",
                ))
            if re.search(r"yum\s+install", line) and not re.search(r"yum\s+clean", line):
                findings.append(_docker_finding(
                    "iac.dockerfile.yum-no-cleanup", "low", "high",
                    "yum install without cache cleanup in same RUN",
                    "yum install is used without cleaning the cache in the same RUN instruction. "
                    "Add '&& yum clean all' to reduce image size.",
                    rel_path, line_num, line[:200], "CWE-459", "A05:2021",
                ))
            # --- Apt-get install without pinned versions ---
            if re.search(r"apt-get\s+install", line):
                # Check for packages without version pinning (pkg=version)
                packages_part = re.sub(r".*apt-get\s+install\s+", "", line)
                packages_part = re.sub(r"&&.*", "", packages_part)  # trim after &&
                packages = [p for p in packages_part.split() if not p.startswith("-")]
                unpinned = [p for p in packages if "=" not in p and p.strip()]
                if unpinned and len(unpinned) > 0:
                    findings.append(_docker_finding(
                        "iac.dockerfile.apt-no-pin-versions", "low", "medium",
                        "apt-get install without pinned package versions",
                        f"Packages installed without version pinning: {', '.join(unpinned[:5])}. "
                        "Pin versions (e.g. pkg=1.2.3) for reproducible builds.",
                        rel_path, line_num, line[:200], "CWE-829", "A06:2021",
                    ))

        # --- SHELL instruction (exec form vs shell form check) ---
        if re.match(r"^(RUN|CMD|ENTRYPOINT)\s+(?!\[)", line, re.IGNORECASE):
            instr = line.split()[0].upper()
            if instr in ("CMD", "ENTRYPOINT"):
                findings.append(_docker_finding(
                    "iac.dockerfile.shell-form", "low", "medium",
                    f"{instr} uses shell form instead of exec form",
                    f"The {instr} instruction uses shell form. Prefer exec form (JSON array) "
                    "so the process receives signals directly and PID 1 works correctly.",
                    rel_path, line_num, line[:200], "CWE-693", "A05:2021",
                ))

        # --- MAINTAINER deprecated ---
        if re.match(r"^MAINTAINER\s+", line, re.IGNORECASE):
            has_maintainer = True
            findings.append(_docker_finding(
                "iac.dockerfile.deprecated-maintainer", "low", "high",
                "Deprecated MAINTAINER instruction used",
                "MAINTAINER is deprecated. Use a LABEL instruction instead: "
                "LABEL maintainer=\"name@example.com\".",
                rel_path, line_num, line[:200], "CWE-477", "A06:2021",
            ))

        # --- WORKDIR with relative path ---
        workdir_match = re.match(r"^WORKDIR\s+(\S+)", line, re.IGNORECASE)
        if workdir_match:
            wd = workdir_match.group(1)
            if not wd.startswith("/") and not wd.startswith("$"):
                findings.append(_docker_finding(
                    "iac.dockerfile.workdir-relative", "low", "high",
                    f"WORKDIR uses relative path: {wd}",
                    "WORKDIR should use an absolute path for clarity and predictability. "
                    "Relative paths depend on the previous WORKDIR and can be confusing.",
                    rel_path, line_num, line[:200], "CWE-426", "A05:2021",
                ))

        # --- EXPOSE range ---
        expose_match = re.match(r"^EXPOSE\s+(.*)", line, re.IGNORECASE)
        if expose_match:
            ports_str = expose_match.group(1)
            range_match = re.search(r"(\d+)-(\d+)", ports_str)
            if range_match:
                low, high = int(range_match.group(1)), int(range_match.group(2))
                if high - low > 100:
                    findings.append(_docker_finding(
                        "iac.dockerfile.expose-large-range", "medium", "high",
                        f"EXPOSE exposes a large port range: {range_match.group(0)}",
                        "Exposing a large range of ports increases the attack surface. "
                        "Only expose the specific ports your application needs.",
                        rel_path, line_num, line[:200], "CWE-284", "A01:2021",
                    ))

    # --- Missing USER (running as root) ---
    if not has_user:
        findings.append(_docker_finding(
            "iac.dockerfile.no-user", "high", "high",
            "Dockerfile has no USER instruction — container runs as root",
            "Without a USER instruction the container runs as root. Add a non-root USER "
            "instruction (e.g. USER 1001) to reduce the impact of container breakouts.",
            rel_path, 1, "", "CWE-250", "A01:2021",
        ))

    # --- Missing HEALTHCHECK ---
    if not has_healthcheck:
        findings.append(_docker_finding(
            "iac.dockerfile.missing-healthcheck", "low", "high",
            "Dockerfile has no HEALTHCHECK instruction",
            "Without HEALTHCHECK, orchestrators cannot determine container health. "
            "Add a HEALTHCHECK to enable automated restart of unhealthy containers.",
            rel_path, 1, "", "CWE-693", "A05:2021",
        ))

    # --- Multi-stage build check (single FROM for production) ---
    if from_count == 1:
        # Heuristic: if there is a build tool reference, suggest multi-stage
        full_text = "".join(lines)
        if re.search(r"(npm\s+run\s+build|go\s+build|mvn\s+package|gradle\s+build|cargo\s+build|make\s+build)", full_text):
            findings.append(_docker_finding(
                "iac.dockerfile.no-multi-stage", "low", "medium",
                "Single-stage build with build tools present",
                "The Dockerfile has only one FROM stage but uses build tools. Use a "
                "multi-stage build to separate build dependencies from the runtime image.",
                rel_path, 1, "", "CWE-459", "A05:2021",
            ))

    # --- Missing .dockerignore ---
    dockerfile_dir = os.path.dirname(rel_path) or "."
    # Deferred to scan_iac which has the source_path context.

    return findings


def _docker_finding(
    rule_id: str, severity: str, confidence: str,
    title: str, description: str,
    file_path: str, line: int, snippet: str,
    cwe_id: str, owasp: str,
) -> dict:
    return {
        "rule_id": rule_id,
        "rule_source": "iac",
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "description": description,
        "file_path": file_path,
        "line_start": line,
        "line_end": line,
        "code_snippet": snippet[:2000],
        "cwe_id": cwe_id,
        "owasp_category": owasp,
        "fingerprint": _fingerprint(rule_id, file_path, line),
    }


# ═══════════════════════════════════════════════════════════════════════════
# CloudFormation checks
# ═══════════════════════════════════════════════════════════════════════════
def _scan_cloudformation(lines: list[str], rel_path: str) -> list[dict]:
    findings: list[dict] = []
    full_text = "".join(lines)

    # --- Public S3 bucket policy ---
    for m in re.finditer(r'(PublicRead|PublicReadWrite|public-read)', full_text):
        ln = full_text[:m.start()].count("\n") + 1
        findings.append(_cfn_finding(
            "iac.cloudformation.public-s3", "high", "high",
            "S3 bucket configured with public access",
            "The CloudFormation template sets a public access policy on an S3 bucket. "
            "Use private access and explicit bucket policies.",
            rel_path, ln, m.group(0), "CWE-284", "A01:2021",
        ))

    # --- Open security group (0.0.0.0/0) ---
    for m in re.finditer(r"CidrIp\s*:\s*['\"]?0\.0\.0\.0/0['\"]?", full_text):
        ln = full_text[:m.start()].count("\n") + 1
        findings.append(_cfn_finding(
            "iac.cloudformation.open-security-group", "high", "high",
            "Security group allows ingress from 0.0.0.0/0",
            "A security group rule permits inbound traffic from any IP address. "
            "Restrict the CIDR to required source addresses.",
            rel_path, ln, m.group(0), "CWE-284", "A01:2021",
        ))

    # Also match CidrIpv6 ::/0
    for m in re.finditer(r"CidrIpv6\s*:\s*['\"]?::/0['\"]?", full_text):
        ln = full_text[:m.start()].count("\n") + 1
        findings.append(_cfn_finding(
            "iac.cloudformation.open-security-group-ipv6", "high", "high",
            "Security group allows ingress from ::/0 (all IPv6)",
            "A security group rule permits inbound traffic from any IPv6 address. "
            "Restrict the CIDR to required source addresses.",
            rel_path, ln, m.group(0), "CWE-284", "A01:2021",
        ))

    # --- Missing encryption ---
    if re.search(r"AWS::RDS::DBInstance", full_text) and not re.search(
        r"StorageEncrypted\s*:\s*true", full_text, re.IGNORECASE,
    ):
        findings.append(_cfn_finding(
            "iac.cloudformation.unencrypted-rds", "high", "medium",
            "RDS instance missing storage encryption",
            "The RDS instance in the CloudFormation template does not have StorageEncrypted "
            "set to true. Enable encryption at rest.",
            rel_path, 1, "", "CWE-311", "A02:2021",
        ))

    if re.search(r"AWS::S3::Bucket", full_text) and not re.search(
        r"(BucketEncryption|ServerSideEncryption)", full_text
    ):
        findings.append(_cfn_finding(
            "iac.cloudformation.unencrypted-s3", "high", "medium",
            "S3 bucket missing encryption configuration",
            "The S3 bucket in the CloudFormation template does not have server-side encryption. "
            "Add BucketEncryption with SSE-S3 or SSE-KMS.",
            rel_path, 1, "", "CWE-311", "A02:2021",
        ))

    # --- Overly permissive IAM ---
    # Look for Action: "*" paired with Resource: "*" and Effect: Allow
    if re.search(r"Effect\s*:\s*Allow", full_text) and re.search(
        r"Action\s*:\s*['\"]?\*['\"]?", full_text
    ) and re.search(r"Resource\s*:\s*['\"]?\*['\"]?", full_text):
        findings.append(_cfn_finding(
            "iac.cloudformation.overly-permissive-iam", "critical", "high",
            "IAM policy grants full access (Action: *, Resource: *)",
            "The CloudFormation template contains an IAM policy that allows all actions on all "
            "resources. Apply least-privilege access.",
            rel_path, 1, "", "CWE-250", "A01:2021",
        ))

    # --- ALB security: redirect to HTTPS ---
    if re.search(r"AWS::ElasticLoadBalancingV2::Listener", full_text):
        if re.search(r"Protocol\s*:\s*['\"]?HTTP['\"]?", full_text) and not re.search(
            r"(redirect|RedirectConfig|HTTPS)", full_text, re.IGNORECASE
        ):
            findings.append(_cfn_finding(
                "iac.cloudformation.alb-no-https-redirect", "high", "high",
                "ALB listener on HTTP without redirect to HTTPS",
                "An ALB listener is configured on HTTP without a redirect action to HTTPS. "
                "Add a redirect rule to enforce HTTPS.",
                rel_path, 1, "", "CWE-319", "A02:2021",
            ))

    # --- NLB access logs ---
    if re.search(r"AWS::ElasticLoadBalancingV2::LoadBalancer", full_text):
        if not re.search(r"access_logs\.s3\.enabled|AccessLoggingPolicy", full_text, re.IGNORECASE):
            findings.append(_cfn_finding(
                "iac.cloudformation.nlb-no-access-logs", "medium", "medium",
                "Load balancer missing access logging",
                "The load balancer does not have access logging enabled. Enable access logs "
                "to capture request metadata for monitoring and forensics.",
                rel_path, 1, "", "CWE-778", "A09:2021",
            ))

    # --- WAF association ---
    if (re.search(r"AWS::ApiGateway::RestApi", full_text) or
            re.search(r"AWS::ElasticLoadBalancingV2::LoadBalancer", full_text)):
        if not re.search(r"(AWS::WAFv2|AWS::WAF|WebACL)", full_text):
            findings.append(_cfn_finding(
                "iac.cloudformation.no-waf-association", "medium", "medium",
                "API Gateway or ALB defined without WAF association",
                "An API Gateway or load balancer is defined without a WAF WebACL. Attach "
                "a WAF to filter malicious traffic.",
                rel_path, 1, "", "CWE-693", "A05:2021",
            ))

    # --- CloudFront OAI ---
    if re.search(r"AWS::CloudFront::Distribution", full_text):
        if re.search(r"S3Origin", full_text, re.IGNORECASE) and not re.search(
            r"(OriginAccessIdentity|OriginAccessControl)", full_text
        ):
            findings.append(_cfn_finding(
                "iac.cloudformation.cloudfront-no-oai", "high", "high",
                "CloudFront S3 origin without Origin Access Identity",
                "CloudFront distribution uses an S3 origin without OAI or OAC. Configure "
                "Origin Access Identity to restrict direct S3 access.",
                rel_path, 1, "", "CWE-284", "A01:2021",
            ))

    # --- API Gateway auth ---
    if re.search(r"AWS::ApiGateway::Method", full_text):
        if re.search(r"AuthorizationType\s*:\s*['\"]?NONE['\"]?", full_text):
            for m in re.finditer(r"AuthorizationType\s*:\s*['\"]?NONE['\"]?", full_text):
                ln = full_text[:m.start()].count("\n") + 1
                findings.append(_cfn_finding(
                    "iac.cloudformation.apigw-no-auth", "high", "high",
                    "API Gateway method without authorization",
                    "An API Gateway method has AuthorizationType set to NONE. Add an "
                    "authorizer (Cognito, Lambda, IAM) to protect the endpoint.",
                    rel_path, ln, m.group(0), "CWE-306", "A07:2021",
                ))

    # --- SNS encryption ---
    if re.search(r"AWS::SNS::Topic", full_text) and not re.search(
        r"KmsMasterKeyId", full_text
    ):
        findings.append(_cfn_finding(
            "iac.cloudformation.sns-no-encryption", "medium", "high",
            "SNS topic missing KMS encryption",
            "The SNS topic does not have KmsMasterKeyId set. Enable KMS encryption "
            "to protect message data at rest.",
            rel_path, 1, "", "CWE-311", "A02:2021",
        ))

    # --- SQS encryption ---
    if re.search(r"AWS::SQS::Queue", full_text) and not re.search(
        r"KmsMasterKeyId", full_text
    ):
        findings.append(_cfn_finding(
            "iac.cloudformation.sqs-no-encryption", "medium", "high",
            "SQS queue missing KMS encryption",
            "The SQS queue does not have KmsMasterKeyId set. Enable KMS encryption "
            "to protect message data at rest.",
            rel_path, 1, "", "CWE-311", "A02:2021",
        ))

    # --- DynamoDB encryption ---
    if re.search(r"AWS::DynamoDB::Table", full_text) and not re.search(
        r"SSESpecification", full_text
    ):
        findings.append(_cfn_finding(
            "iac.cloudformation.dynamodb-no-encryption", "high", "high",
            "DynamoDB table missing server-side encryption",
            "The DynamoDB table does not have SSESpecification configured. Enable SSE "
            "with a KMS key to protect data at rest.",
            rel_path, 1, "", "CWE-311", "A02:2021",
        ))

    # --- DynamoDB backup (PITR) ---
    if re.search(r"AWS::DynamoDB::Table", full_text) and not re.search(
        r"PointInTimeRecoverySpecification", full_text
    ):
        findings.append(_cfn_finding(
            "iac.cloudformation.dynamodb-no-pitr", "medium", "medium",
            "DynamoDB table missing point-in-time recovery",
            "The DynamoDB table does not have PointInTimeRecoverySpecification. Enable "
            "PITR for continuous backups.",
            rel_path, 1, "", "CWE-693", "A05:2021",
        ))

    # --- RDS multi-AZ ---
    if re.search(r"AWS::RDS::DBInstance", full_text):
        if not re.search(r"MultiAZ\s*:\s*true", full_text, re.IGNORECASE) and not re.search(
            r"MultiAZ\s*:\s*['\"]?true['\"]?", full_text
        ):
            findings.append(_cfn_finding(
                "iac.cloudformation.rds-no-multi-az", "medium", "medium",
                "RDS instance not configured for Multi-AZ",
                "The RDS instance does not have MultiAZ enabled. Enable Multi-AZ "
                "for high availability and automatic failover.",
                rel_path, 1, "", "CWE-693", "A05:2021",
            ))

    # --- RDS deletion protection ---
    if re.search(r"AWS::RDS::DBInstance", full_text):
        if not re.search(r"DeletionProtection\s*:\s*true", full_text, re.IGNORECASE):
            findings.append(_cfn_finding(
                "iac.cloudformation.rds-no-deletion-protection", "medium", "high",
                "RDS instance missing deletion protection",
                "The RDS instance does not have DeletionProtection enabled. Enable it "
                "to prevent accidental database deletion.",
                rel_path, 1, "", "CWE-693", "A05:2021",
            ))

    # --- ECS task role ---
    if re.search(r"AWS::ECS::TaskDefinition", full_text) and not re.search(
        r"TaskRoleArn", full_text
    ):
        findings.append(_cfn_finding(
            "iac.cloudformation.ecs-no-task-role", "medium", "medium",
            "ECS task definition missing task role",
            "The ECS task definition does not specify a TaskRoleArn. Without a task role, "
            "containers cannot access AWS services securely.",
            rel_path, 1, "", "CWE-284", "A01:2021",
        ))

    # --- CodeBuild encryption ---
    if re.search(r"AWS::CodeBuild::Project", full_text) and not re.search(
        r"EncryptionKey", full_text
    ):
        findings.append(_cfn_finding(
            "iac.cloudformation.codebuild-no-encryption", "medium", "medium",
            "CodeBuild project missing encryption key",
            "The CodeBuild project does not specify an EncryptionKey. Configure a KMS key "
            "to encrypt build artifacts.",
            rel_path, 1, "", "CWE-311", "A02:2021",
        ))

    # --- Secrets Manager rotation ---
    if re.search(r"AWS::SecretsManager::Secret", full_text) and not re.search(
        r"RotationSchedule|RotationLambdaARN|RotationRules", full_text
    ):
        findings.append(_cfn_finding(
            "iac.cloudformation.secret-no-rotation", "medium", "medium",
            "Secrets Manager secret without rotation configured",
            "The secret does not have automatic rotation configured. Set up a "
            "RotationSchedule to rotate secrets automatically.",
            rel_path, 1, "", "CWE-798", "A07:2021",
        ))

    # --- Step Functions logging ---
    if re.search(r"AWS::StepFunctions::StateMachine", full_text) and not re.search(
        r"LoggingConfiguration", full_text
    ):
        findings.append(_cfn_finding(
            "iac.cloudformation.stepfunctions-no-logging", "medium", "medium",
            "Step Functions state machine without logging",
            "The state machine does not have LoggingConfiguration. Enable logging to "
            "capture execution history for debugging and audit.",
            rel_path, 1, "", "CWE-778", "A09:2021",
        ))

    return findings


def _cfn_finding(
    rule_id: str, severity: str, confidence: str,
    title: str, description: str,
    file_path: str, line: int, snippet: str,
    cwe_id: str, owasp: str,
) -> dict:
    return {
        "rule_id": rule_id,
        "rule_source": "iac",
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "description": description,
        "file_path": file_path,
        "line_start": line,
        "line_end": line,
        "code_snippet": snippet[:2000],
        "cwe_id": cwe_id,
        "owasp_category": owasp,
        "fingerprint": _fingerprint(rule_id, file_path, line),
    }


# ═══════════════════════════════════════════════════════════════════════════
# Helm values.yaml checks
# ═══════════════════════════════════════════════════════════════════════════
def _scan_helm_values(lines: list[str], rel_path: str) -> list[dict]:
    findings: list[dict] = []
    full_text = "".join(lines)

    # --- Insecure defaults: privileged ---
    for m in re.finditer(r"privileged\s*:\s*true", full_text):
        ln = full_text[:m.start()].count("\n") + 1
        findings.append({
            "rule_id": "iac.helm.privileged-default",
            "rule_source": "iac",
            "severity": "critical",
            "confidence": "medium",
            "title": "Helm values.yaml defaults to privileged container",
            "description": "The default values enable privileged mode for containers. "
                           "Override with privileged: false in your values override.",
            "file_path": rel_path,
            "line_start": ln,
            "line_end": ln,
            "code_snippet": m.group(0),
            "cwe_id": "CWE-250",
            "owasp_category": "A01:2021",
            "fingerprint": _fingerprint("iac.helm.privileged-default", rel_path, ln),
        })

    # --- Insecure defaults: runAsRoot ---
    for m in re.finditer(r"runAsUser\s*:\s*0\b", full_text):
        ln = full_text[:m.start()].count("\n") + 1
        findings.append({
            "rule_id": "iac.helm.run-as-root-default",
            "rule_source": "iac",
            "severity": "high",
            "confidence": "medium",
            "title": "Helm values.yaml defaults to running as root",
            "description": "The default values set runAsUser: 0 (root). Use a non-root user.",
            "file_path": rel_path,
            "line_start": ln,
            "line_end": ln,
            "code_snippet": m.group(0),
            "cwe_id": "CWE-250",
            "owasp_category": "A01:2021",
            "fingerprint": _fingerprint("iac.helm.run-as-root-default", rel_path, ln),
        })

    # --- hostNetwork default ---
    for m in re.finditer(r"hostNetwork\s*:\s*true", full_text):
        ln = full_text[:m.start()].count("\n") + 1
        findings.append({
            "rule_id": "iac.helm.host-network-default",
            "rule_source": "iac",
            "severity": "high",
            "confidence": "medium",
            "title": "Helm values.yaml defaults to hostNetwork",
            "description": "The default values enable hostNetwork which shares the host "
                           "network namespace. Set hostNetwork: false.",
            "file_path": rel_path,
            "line_start": ln,
            "line_end": ln,
            "code_snippet": m.group(0),
            "cwe_id": "CWE-284",
            "owasp_category": "A01:2021",
            "fingerprint": _fingerprint("iac.helm.host-network-default", rel_path, ln),
        })

    # --- Image tag :latest ---
    for m in re.finditer(r"tag\s*:\s*['\"]?latest['\"]?", full_text):
        ln = full_text[:m.start()].count("\n") + 1
        findings.append({
            "rule_id": "iac.helm.latest-tag-default",
            "rule_source": "iac",
            "severity": "medium",
            "confidence": "high",
            "title": "Helm values.yaml defaults to :latest image tag",
            "description": "Using :latest makes deployments non-reproducible. Pin to a "
                           "specific version tag.",
            "file_path": rel_path,
            "line_start": ln,
            "line_end": ln,
            "code_snippet": m.group(0),
            "cwe_id": "CWE-829",
            "owasp_category": "A06:2021",
            "fingerprint": _fingerprint("iac.helm.latest-tag-default", rel_path, ln),
        })

    # --- Missing security context in values ---
    if not re.search(r"securityContext\s*:", full_text):
        findings.append({
            "rule_id": "iac.helm.missing-security-context",
            "rule_source": "iac",
            "severity": "medium",
            "confidence": "medium",
            "title": "Helm values.yaml missing securityContext defaults",
            "description": "The values file does not define securityContext defaults. "
                           "Add securityContext with runAsNonRoot, readOnlyRootFilesystem, etc.",
            "file_path": rel_path,
            "line_start": 1,
            "line_end": 1,
            "code_snippet": "",
            "cwe_id": "CWE-250",
            "owasp_category": "A01:2021",
            "fingerprint": _fingerprint("iac.helm.missing-security-context", rel_path, 1),
        })

    # --- Default service account usage ---
    sa_match = re.search(r"serviceAccount\s*:\s*\n\s*name\s*:\s*['\"]?default['\"]?", full_text)
    if sa_match:
        ln = full_text[:sa_match.start()].count("\n") + 1
        findings.append({
            "rule_id": "iac.helm.default-service-account",
            "rule_source": "iac",
            "severity": "medium",
            "confidence": "high",
            "title": "Helm values.yaml uses default service account",
            "description": "The values file specifies the 'default' service account. "
                           "Create and use a dedicated service account with minimal RBAC.",
            "file_path": rel_path,
            "line_start": ln,
            "line_end": ln,
            "code_snippet": sa_match.group(0),
            "cwe_id": "CWE-284",
            "owasp_category": "A01:2021",
            "fingerprint": _fingerprint("iac.helm.default-service-account", rel_path, ln),
        })

    # --- Missing network policy template ---
    if not re.search(r"networkPolicy\s*:", full_text):
        findings.append({
            "rule_id": "iac.helm.missing-network-policy",
            "rule_source": "iac",
            "severity": "low",
            "confidence": "low",
            "title": "Helm values.yaml missing network policy configuration",
            "description": "The values file does not include a networkPolicy section. "
                           "Add network policy defaults to enable network segmentation.",
            "file_path": rel_path,
            "line_start": 1,
            "line_end": 1,
            "code_snippet": "",
            "cwe_id": "CWE-284",
            "owasp_category": "A01:2021",
            "fingerprint": _fingerprint("iac.helm.missing-network-policy", rel_path, 1),
        })

    # --- Tiller deprecated references ---
    for m in re.finditer(r"[Tt]iller", full_text):
        ln = full_text[:m.start()].count("\n") + 1
        findings.append({
            "rule_id": "iac.helm.tiller-reference",
            "rule_source": "iac",
            "severity": "medium",
            "confidence": "high",
            "title": "Reference to deprecated Tiller component",
            "description": "The values file references Tiller which was removed in Helm 3. "
                           "Tiller had significant security issues. Upgrade to Helm 3.",
            "file_path": rel_path,
            "line_start": ln,
            "line_end": ln,
            "code_snippet": m.group(0),
            "cwe_id": "CWE-477",
            "owasp_category": "A06:2021",
            "fingerprint": _fingerprint("iac.helm.tiller-reference", rel_path, ln),
        })

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# .dockerignore check (called from scan_iac with source_path context)
# ═══════════════════════════════════════════════════════════════════════════
def _check_dockerignore(source_path: str, dockerfile_rel: str) -> list[dict]:
    """Check if .dockerignore exists alongside a Dockerfile."""
    findings: list[dict] = []
    dockerfile_abs = os.path.join(source_path, dockerfile_rel)
    dockerfile_dir = os.path.dirname(dockerfile_abs)
    dockerignore = os.path.join(dockerfile_dir, ".dockerignore")

    if not os.path.isfile(dockerignore):
        findings.append({
            "rule_id": "iac.dockerfile.missing-dockerignore",
            "rule_source": "iac",
            "severity": "medium",
            "confidence": "high",
            "title": "Missing .dockerignore file",
            "description": (
                f"No .dockerignore found alongside {dockerfile_rel}. Without .dockerignore, "
                "sensitive files (e.g. .env, .git, node_modules) may be included in the Docker "
                "build context, increasing image size and risking secret exposure."
            ),
            "file_path": dockerfile_rel,
            "line_start": 1,
            "line_end": 1,
            "code_snippet": "",
            "cwe_id": "CWE-200",
            "owasp_category": "A05:2021",
            "fingerprint": _fingerprint("iac.dockerfile.missing-dockerignore", dockerfile_rel, 1),
        })

    return findings


# ═══════════════════════════════════════════════════════════════════════════
# Ansible checks
# ═══════════════════════════════════════════════════════════════════════════
def _scan_ansible(lines: list[str], rel_path: str) -> list[dict]:
    findings: list[dict] = []
    full_text = "".join(lines)

    # --- become without become_user ---
    for m in re.finditer(r"become\s*:\s*(yes|true)", full_text, re.IGNORECASE):
        context_start = max(0, m.start() - 500)
        context_end = min(len(full_text), m.end() + 500)
        context = full_text[context_start:context_end]
        if "become_user" not in context:
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_ansible_finding(
                "iac.ansible.become-without-user", "medium", "medium",
                "become: yes without become_user specified",
                "The task uses 'become: yes' without specifying become_user. This defaults "
                "to root. Explicitly set become_user to the least-privileged user needed.",
                rel_path, ln, m.group(0), "CWE-250", "A01:2021",
            ))

    # --- shell module instead of command ---
    for m in re.finditer(r"^\s*shell\s*:", full_text, re.MULTILINE):
        ln = full_text[:m.start()].count("\n") + 1
        # Check if the shell features (pipes, redirects, env vars) are actually used
        task_end = full_text.find("\n-", m.end())
        if task_end == -1:
            task_end = len(full_text)
        task_block = full_text[m.start():task_end]
        if not re.search(r"[|><;$`]", task_block):
            findings.append(_ansible_finding(
                "iac.ansible.shell-instead-of-command", "low", "medium",
                "shell module used when command module would suffice",
                "The task uses the shell module but does not appear to use shell features "
                "(pipes, redirects, variables). Use the command module for safer execution.",
                rel_path, ln, m.group(0), "CWE-78", "A03:2021",
            ))

    # --- no_log for secrets ---
    for m in re.finditer(
        r"(password|secret|token|api_key|private_key)\s*:", full_text, re.IGNORECASE
    ):
        # Check if no_log is set in the surrounding task
        context_start = max(0, m.start() - 500)
        context_end = min(len(full_text), m.end() + 500)
        context = full_text[context_start:context_end]
        # Find the task boundary
        if "no_log" not in context:
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_ansible_finding(
                "iac.ansible.missing-no-log", "high", "medium",
                f"Task with sensitive field '{m.group(1)}' missing no_log",
                "A task handles sensitive data but does not set no_log: true. Without "
                "no_log, secrets may appear in Ansible output and logs.",
                rel_path, ln, m.group(0), "CWE-532", "A09:2021",
            ))

    # --- Package pinning ---
    for m in re.finditer(r"(apt|yum|dnf|pip)\s*:", full_text):
        task_end = full_text.find("\n-", m.end())
        if task_end == -1:
            task_end = min(len(full_text), m.end() + 1000)
        task_block = full_text[m.start():task_end]
        name_match = re.search(r"name\s*:\s*(\S+)", task_block)
        if name_match:
            pkg = name_match.group(1)
            if "=" not in pkg and "version" not in task_block.lower() and "state: latest" in task_block:
                ln = full_text[:m.start()].count("\n") + 1
                findings.append(_ansible_finding(
                    "iac.ansible.unpinned-package", "low", "medium",
                    f"Package '{pkg}' installed with state: latest and no version pin",
                    "The package is installed with state: latest without a pinned version. "
                    "Pin the version for reproducible deployments.",
                    rel_path, ln, name_match.group(0), "CWE-829", "A06:2021",
                ))

    # --- Git clone without version ---
    for m in re.finditer(r"git\s*:", full_text):
        task_end = full_text.find("\n-", m.end())
        if task_end == -1:
            task_end = min(len(full_text), m.end() + 1000)
        task_block = full_text[m.start():task_end]
        if "repo" in task_block and "version" not in task_block:
            ln = full_text[:m.start()].count("\n") + 1
            findings.append(_ansible_finding(
                "iac.ansible.git-no-version", "medium", "high",
                "Git module used without specifying version/tag",
                "The git module clones a repository without pinning a version, tag, or "
                "commit. Pin to a specific ref to ensure reproducible deployments.",
                rel_path, ln, m.group(0), "CWE-829", "A08:2021",
            ))

    return findings


def _ansible_finding(
    rule_id: str, severity: str, confidence: str,
    title: str, description: str,
    file_path: str, line: int, snippet: str,
    cwe_id: str, owasp: str,
) -> dict:
    return {
        "rule_id": rule_id,
        "rule_source": "iac",
        "severity": severity,
        "confidence": confidence,
        "title": title,
        "description": description,
        "file_path": file_path,
        "line_start": line,
        "line_end": line,
        "code_snippet": snippet[:2000],
        "cwe_id": cwe_id,
        "owasp_category": owasp,
        "fingerprint": _fingerprint(rule_id, file_path, line),
    }


# ═══════════════════════════════════════════════════════════════════════════
# Main entry point
# ═══════════════════════════════════════════════════════════════════════════
def scan_iac(source_path: str) -> list[dict]:
    """Scan a directory tree for IaC misconfigurations.

    Detects file types automatically and runs the appropriate checks.

    Args:
        source_path: Root directory to scan.

    Returns:
        List of finding dicts matching the SastFinding schema.
    """
    findings: list[dict] = []
    files_scanned = 0

    for root, dirs, filenames in os.walk(source_path):
        # Prune skippable directories
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for fname in filenames:
            if files_scanned >= 50000:
                logger.warning("IaC scan file limit (50 000) reached — stopping")
                break

            ext = os.path.splitext(fname)[1].lower()
            if ext in SKIP_EXTENSIONS:
                continue

            fpath = os.path.join(root, fname)

            # Size guard
            try:
                if os.path.getsize(fpath) > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue

            # Read file
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except (OSError, UnicodeDecodeError):
                continue

            # Quick binary check: if file contains null bytes, skip
            if "\x00" in content[:8192]:
                continue

            rel_path = os.path.relpath(fpath, source_path)
            lines = content.splitlines(keepends=True)
            files_scanned += 1

            # Dispatch to the appropriate scanner
            if _is_terraform(fpath):
                findings.extend(_scan_terraform(lines, rel_path))

            elif _is_dockerfile(fpath):
                findings.extend(_scan_dockerfile(lines, rel_path))
                findings.extend(_check_dockerignore(source_path, rel_path))

            elif _is_cloudformation(fpath, content):
                findings.extend(_scan_cloudformation(lines, rel_path))

            elif _is_helm_values(fpath):
                findings.extend(_scan_helm_values(lines, rel_path))

            elif _is_kubernetes(fpath, content):
                findings.extend(_scan_kubernetes(lines, rel_path))

            elif _is_ansible(fpath, content):
                findings.extend(_scan_ansible(lines, rel_path))

    # Deduplicate by fingerprint
    seen: set[str] = set()
    deduped: list[dict] = []
    for f in findings:
        fp = f.get("fingerprint", "")
        if fp and fp in seen:
            continue
        seen.add(fp)
        deduped.append(f)

    logger.info("IaC scan complete: %d files scanned, %d findings", files_scanned, len(deduped))
    return deduped
