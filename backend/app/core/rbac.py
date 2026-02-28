"""Role-Based Access Control per PRD. Use: require_tester_plus = require_roles(get_current_user, 'admin','lead','tester')"""
from fastapi import HTTPException, Depends
from app.models.user import User

ROLES = {"super_admin", "admin", "lead", "tester", "viewer"}


def require_roles(get_user_dep, *allowed: str):
    """Returns a Depends() compatible dependency that requires one of the allowed roles."""
    def _check(current_user: User = Depends(get_user_dep)) -> User:
        if current_user.role not in allowed:
            raise HTTPException(403, f"Access denied. Required role: {', '.join(allowed)}")
        return current_user
    return _check
