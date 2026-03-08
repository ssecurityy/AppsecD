"""Custom rule authoring — allow orgs to define and manage custom Semgrep rules.

Provides:
- CRUD for custom Semgrep YAML rules per organization
- Rule validation and testing against sample code
- Rule injection into Semgrep runner at scan time
- Rule versioning and enable/disable per project
"""
import json
import logging
import os
import subprocess
import tempfile
import uuid
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


class CustomRuleManager:
    """Manages custom Semgrep rules for organizations."""

    @staticmethod
    async def create_rule(
        organization_id: str,
        name: str,
        rule_yaml: str,
        description: str = "",
        created_by: str | None = None,
    ) -> dict:
        """Create a new custom rule for an organization.

        Args:
            organization_id: UUID of the organization
            name: Human-readable rule name
            rule_yaml: Valid Semgrep YAML rule content
            description: Optional description
            created_by: UUID of the user creating the rule

        Returns:
            Created rule record dict
        """
        # Validate YAML syntax
        import yaml
        try:
            parsed = yaml.safe_load(rule_yaml)
            if not isinstance(parsed, dict) or "rules" not in parsed:
                raise ValueError("Rule YAML must contain a 'rules' key with at least one rule")
        except yaml.YAMLError as e:
            raise ValueError(f"Invalid YAML syntax: {e}")

        # Validate rule structure
        rules = parsed.get("rules", [])
        if not rules:
            raise ValueError("At least one rule must be defined")

        for rule in rules:
            if not rule.get("id"):
                raise ValueError("Each rule must have an 'id' field")
            if not rule.get("patterns") and not rule.get("pattern") and not rule.get("pattern-either"):
                raise ValueError(f"Rule '{rule.get('id')}' must have a pattern, patterns, or pattern-either field")

        # Store in database
        try:
            from app.core.database import AsyncSessionLocal
            from sqlalchemy import text
            import uuid as _uuid

            rule_id = str(_uuid.uuid4())
            async with AsyncSessionLocal() as db:
                await db.execute(text("""
                    INSERT INTO sast_custom_rules (id, organization_id, name, description, rule_yaml, is_active, created_by, created_at)
                    VALUES (:id, :org_id, :name, :desc, :yaml, true, :created_by, :now)
                """), {
                    "id": rule_id,
                    "org_id": organization_id,
                    "name": name,
                    "desc": description,
                    "yaml": rule_yaml,
                    "created_by": created_by,
                    "now": datetime.utcnow(),
                })
                await db.commit()

            return {
                "id": rule_id,
                "name": name,
                "description": description,
                "is_active": True,
                "rule_count": len(rules),
                "rule_ids": [r.get("id") for r in rules],
            }
        except Exception as e:
            logger.error("Failed to store custom rule: %s", e)
            raise ValueError(f"Failed to store rule: {e}")

    @staticmethod
    async def list_rules(organization_id: str, active_only: bool = True) -> list[dict]:
        """List all custom rules for an organization."""
        try:
            from app.core.database import AsyncSessionLocal
            from sqlalchemy import text

            async with AsyncSessionLocal() as db:
                query = "SELECT id, name, description, is_active, created_at FROM sast_custom_rules WHERE organization_id = :org_id"
                if active_only:
                    query += " AND is_active = true"
                query += " ORDER BY created_at DESC"

                result = await db.execute(text(query), {"org_id": organization_id})
                return [
                    {
                        "id": str(row[0]),
                        "name": row[1],
                        "description": row[2],
                        "is_active": row[3],
                        "created_at": row[4].isoformat() if row[4] else None,
                    }
                    for row in result.fetchall()
                ]
        except Exception as e:
            logger.error("Failed to list custom rules: %s", e)
            return []

    @staticmethod
    async def get_rule_yaml(rule_id: str) -> str | None:
        """Get the YAML content of a custom rule."""
        try:
            from app.core.database import AsyncSessionLocal
            from sqlalchemy import text

            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    text("SELECT rule_yaml FROM sast_custom_rules WHERE id = :id"),
                    {"id": rule_id},
                )
                row = result.fetchone()
                return row[0] if row else None
        except Exception:
            return None

    @staticmethod
    async def toggle_rule(rule_id: str, is_active: bool) -> bool:
        """Enable or disable a custom rule."""
        try:
            from app.core.database import AsyncSessionLocal
            from sqlalchemy import text

            async with AsyncSessionLocal() as db:
                await db.execute(
                    text("UPDATE sast_custom_rules SET is_active = :active WHERE id = :id"),
                    {"active": is_active, "id": rule_id},
                )
                await db.commit()
                return True
        except Exception:
            return False

    @staticmethod
    async def delete_rule(rule_id: str) -> bool:
        """Delete a custom rule."""
        try:
            from app.core.database import AsyncSessionLocal
            from sqlalchemy import text

            async with AsyncSessionLocal() as db:
                await db.execute(
                    text("DELETE FROM sast_custom_rules WHERE id = :id"),
                    {"id": rule_id},
                )
                await db.commit()
                return True
        except Exception:
            return False

    @staticmethod
    def test_rule(rule_yaml: str, test_code: str, language: str = "python") -> dict:
        """Test a custom rule against sample code.

        Args:
            rule_yaml: Semgrep YAML rule content
            test_code: Sample code to test against
            language: Programming language of the test code

        Returns:
            dict with test results including any matches found
        """
        ext_map = {
            "python": ".py", "javascript": ".js", "typescript": ".ts",
            "java": ".java", "go": ".go", "ruby": ".rb", "php": ".php",
            "csharp": ".cs", "rust": ".rs", "kotlin": ".kt", "swift": ".swift",
        }
        ext = ext_map.get(language.lower(), ".py")

        tmpdir = tempfile.mkdtemp(prefix="sast_rule_test_")
        try:
            # Write rule file
            rule_path = os.path.join(tmpdir, "test_rule.yaml")
            with open(rule_path, "w") as f:
                f.write(rule_yaml)

            # Write test code
            code_path = os.path.join(tmpdir, f"test_code{ext}")
            with open(code_path, "w") as f:
                f.write(test_code)

            # Run semgrep
            result = subprocess.run(
                [
                    "semgrep", "scan",
                    "--config", rule_path,
                    "--json",
                    "--no-git-ignore",
                    code_path,
                ],
                capture_output=True,
                text=True,
                timeout=30,
                cwd=tmpdir,
            )

            try:
                output = json.loads(result.stdout)
                matches = output.get("results", [])
                return {
                    "success": True,
                    "matches": len(matches),
                    "findings": [
                        {
                            "rule_id": m.get("check_id", ""),
                            "line": m.get("start", {}).get("line", 0),
                            "message": m.get("extra", {}).get("message", ""),
                            "severity": m.get("extra", {}).get("severity", ""),
                        }
                        for m in matches
                    ],
                    "errors": output.get("errors", []),
                }
            except json.JSONDecodeError:
                return {
                    "success": False,
                    "error": result.stderr[:500] or "Failed to parse Semgrep output",
                    "matches": 0,
                    "findings": [],
                }

        except subprocess.TimeoutExpired:
            return {"success": False, "error": "Rule test timed out", "matches": 0, "findings": []}
        except FileNotFoundError:
            return {"success": False, "error": "Semgrep not installed", "matches": 0, "findings": []}
        finally:
            import shutil
            shutil.rmtree(tmpdir, ignore_errors=True)

    @staticmethod
    async def get_active_rule_files(organization_id: str, output_dir: str) -> list[str]:
        """Write active custom rules to temp files for Semgrep runner injection.

        Args:
            organization_id: UUID of the organization
            output_dir: Directory to write rule YAML files to

        Returns:
            List of rule file paths ready for Semgrep --config
        """
        rule_files = []
        try:
            from app.core.database import AsyncSessionLocal
            from sqlalchemy import text

            async with AsyncSessionLocal() as db:
                result = await db.execute(
                    text("SELECT id, rule_yaml FROM sast_custom_rules WHERE organization_id = :org_id AND is_active = true"),
                    {"org_id": organization_id},
                )

                for row in result.fetchall():
                    rule_path = os.path.join(output_dir, f"custom_{row[0]}.yaml")
                    with open(rule_path, "w") as f:
                        f.write(row[1])
                    rule_files.append(rule_path)

        except Exception as e:
            logger.warning("Failed to load custom rules: %s", e)

        return rule_files
