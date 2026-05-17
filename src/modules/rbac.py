# By🇭🇷PhonkAlphabet
# By🇭🇷PhonkAlphabet
#!/usr/bin/env python3
"""
Role-Based Access Control (RBAC) Module
"""
from datetime import datetime
from typing import Dict, List, Any

class RBACModule:
    def __init__(self):
        self.roles = {
            "admin": ["read", "write", "execute", "configure", "delete"],
            "responder": ["read", "write", "execute"],
            "analyst": ["read", "execute"],
            "viewer": ["read"]
        }
        self.users = {
            "admin": "admin",
            "analyst1": "analyst",
            "responder1": "responder",
            "viewer1": "viewer"
        }

    def check_permission(self, user: str, action: str) -> bool:
        """Check if user has permission for action"""
        role = self.users.get(user, "viewer")
        return action in self.roles.get(role, [])

    def get_user_role(self, user: str) -> str:
        """Get role for a user"""
        return self.users.get(user, "viewer")

    def list_users(self) -> List[Dict]:
        """List all users and their roles"""
        return [{"user": u, "role": r} for u, r in self.users.items()]

    def get_summary(self) -> Dict:
        return {
            "module": "RBAC",
            "total_users": len(self.users),
            "total_roles": len(self.roles),
            "timestamp": datetime.now().isoformat()
        }
