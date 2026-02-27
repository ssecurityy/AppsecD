"""Achievement badge definitions and award logic."""
from typing import Optional

BADGES = {
    "first_blood": {"name": "First Blood", "icon": "🎯", "trigger": "First vulnerability found in a project"},
    "recon_master": {"name": "Recon Master", "icon": "🔍", "trigger": "Complete Recon phase with 100% coverage"},
    "sql_slayer": {"name": "SQL Slayer", "icon": "💉", "trigger": "Document a confirmed SQL injection finding"},
    "xss_hunter": {"name": "XSS Hunter", "icon": "🕷️", "trigger": "Document 3+ XSS findings"},
    "lock_picker": {"name": "Lock Picker", "icon": "🗝️", "trigger": "Find an authentication bypass vulnerability"},
    "mission_complete": {"name": "Mission Complete", "icon": "🏆", "trigger": "Complete 100% of applicable test cases"},
    "speed_runner": {"name": "Speed Runner", "icon": "⚡", "trigger": "Complete a full project in under 8 hours"},
    "business_brain": {"name": "Business Brain", "icon": "🧠", "trigger": "Find a business logic vulnerability"},
    "tool_master": {"name": "Tool Master", "icon": "🤖", "trigger": "Run 10+ automated tool tests in one project"},
    "on_fire": {"name": "On Fire", "icon": "🔥", "trigger": "Find 5+ vulnerabilities in a single session"},
    "thorough_tester": {"name": "Thorough Tester", "icon": "📋", "trigger": "Zero 'not tested' items at completion"},
    "vapt_veteran": {"name": "VAPT Veteran", "icon": "🌟", "trigger": "Complete 10 projects on the platform"},
}


def check_and_award_badges(
    user_badges: list,
    event: str,
    context: dict,
) -> list[str]:
    """
    Check if user earns new badges based on event. Returns list of newly awarded badge IDs.
    user_badges: current list of badge IDs the user has
    event: e.g. "finding_created", "result_updated", "phase_completed", "project_completed"
    context: event-specific data
    """
    newly_awarded = []
    user_set = set(user_badges or [])

    if event == "finding_created":
        title_lower = (context.get("title") or "").lower()
        desc_lower = (context.get("description") or "").lower()
        combined = title_lower + " " + desc_lower
        if "sql injection" in combined or "sqli" in combined or "sql injection" in combined and "sql_slayer" not in user_set:
            newly_awarded.append("sql_slayer")
        if ("xss" in combined or "cross-site scripting" in combined) and "xss_hunter" not in user_set:
            # XSS Hunter needs 3+ - we check count in context
            if context.get("user_xss_count", 0) >= 3:
                newly_awarded.append("xss_hunter")
        if ("auth" in combined or "bypass" in combined or "authentication" in combined) and "lock_picker" not in user_set:
            newly_awarded.append("lock_picker")
        if ("business logic" in combined or "logic" in combined) and "business_brain" not in user_set:
            newly_awarded.append("business_brain")
        if context.get("is_first_finding_in_project") and "first_blood" not in user_set:
            newly_awarded.append("first_blood")

    elif event == "phase_completed":
        if context.get("phase") == "recon" and "recon_master" not in user_set:
            newly_awarded.append("recon_master")

    elif event == "project_completed":
        if context.get("completion_pct", 0) >= 100 and "mission_complete" not in user_set:
            newly_awarded.append("mission_complete")
        if context.get("zero_not_tested") and "thorough_tester" not in user_set:
            newly_awarded.append("thorough_tester")
        if context.get("completed_under_8h") and "speed_runner" not in user_set:
            newly_awarded.append("speed_runner")

    elif event == "veteran_check":
        if context.get("projects_completed", 0) >= 10 and "vapt_veteran" not in user_set:
            newly_awarded.append("vapt_veteran")

    return [b for b in newly_awarded if b not in user_set]
