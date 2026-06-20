"""
CyberShield Authentication & Authorization Module
===================================================
Enterprise-grade auth system with bcrypt password hashing,
role-based access control (RBAC), session management,
brute force protection, and audit logging.

Roles: citizen, officer, admin
"""

import bcrypt
import streamlit as st
from datetime import datetime, timedelta
import database as db


# ==========================================
# PASSWORD SECURITY (bcrypt)
# ==========================================

def hash_password(plain_password: str) -> str:
    """Hash a plaintext password using bcrypt with 12 rounds."""
    return bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plaintext password against a bcrypt hash."""
    try:
        return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))
    except Exception:
        return False


# ==========================================
# SESSION MANAGEMENT
# ==========================================

def init_session():
    """Initialize all session state keys if they don't exist."""
    defaults = {
        "authenticated": False,
        "username": None,
        "role": None,
        "full_name": None,
        "login_time": None,
        "last_activity": None,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def is_authenticated() -> bool:
    """Check if the current session is authenticated."""
    return st.session_state.get("authenticated", False)


def get_current_user() -> dict:
    """Return current user info from session state."""
    return {
        "username": st.session_state.get("username"),
        "role": st.session_state.get("role"),
        "full_name": st.session_state.get("full_name"),
        "login_time": st.session_state.get("login_time"),
    }


def get_current_role() -> str:
    """Return the role of the current authenticated user."""
    return st.session_state.get("role", "")


def get_current_username() -> str:
    """Return the username of the current authenticated user."""
    return st.session_state.get("username", "")


def check_session_timeout(timeout_minutes: int = 30) -> bool:
    """
    Check if the session has expired due to inactivity.
    Returns True if session is still valid, False if expired.
    """
    if not is_authenticated():
        return False

    last_activity = st.session_state.get("last_activity")
    if last_activity:
        try:
            last_time = datetime.strptime(last_activity, "%Y-%m-%d %H:%M:%S")
            if datetime.now() - last_time > timedelta(minutes=timeout_minutes):
                # Session expired
                username = st.session_state.get("username", "unknown")
                role = st.session_state.get("role", "")
                db.log_audit(username, role, "SESSION_EXPIRED", details=f"Timeout after {timeout_minutes} minutes of inactivity")
                _clear_session()
                return False
        except (ValueError, TypeError):
            pass

    # Update last activity timestamp
    st.session_state["last_activity"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return True


# ==========================================
# LOGIN / LOGOUT
# ==========================================

def login_user(username: str, password: str) -> tuple:
    """
    Attempt to log in a user.
    Returns (success: bool, message: str)
    """
    if not username or not password:
        return False, "Please enter both username and password."

    username = username.strip().lower()

    # Fetch user from database
    user = db.get_user_by_username(username)
    if not user:
        # Don't reveal whether username exists
        return False, "Invalid credentials. Please check your username and password."

    # Check if account is active
    if not user.get("is_active", 1):
        return False, "This account has been deactivated. Contact your administrator."

    # Check brute force lock
    is_locked, failed_count, lock_until = db.is_account_locked(username)
    if is_locked:
        remaining = (lock_until - datetime.now()).seconds // 60
        remaining_sec = (lock_until - datetime.now()).seconds % 60
        db.log_audit(username, user["role"], "LOGIN_BLOCKED", details=f"Account locked. {remaining}m {remaining_sec}s remaining.")
        return False, f"🔒 Account locked due to {failed_count} failed attempts. Try again in {remaining} min {remaining_sec} sec."

    # Verify password
    if not verify_password(password, user["password_hash"]):
        db.increment_failed_attempts(username)
        remaining_attempts = 5 - (failed_count + 1)
        db.log_audit(username, user["role"], "LOGIN_FAILED", details=f"Wrong password. Attempts remaining: {remaining_attempts}")
        if remaining_attempts <= 0:
            return False, "🔒 Account locked for 15 minutes due to too many failed attempts."
        return False, f"Invalid credentials. {remaining_attempts} attempt(s) remaining before lockout."

    # SUCCESS — set session state
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    st.session_state["authenticated"] = True
    st.session_state["username"] = username
    st.session_state["role"] = user["role"]
    st.session_state["full_name"] = user["full_name"]
    st.session_state["login_time"] = now
    st.session_state["last_activity"] = now

    # Update DB
    db.update_user_login(username)

    # Audit
    db.log_audit(username, user["role"], "LOGIN_SUCCESS", details="User authenticated successfully")

    return True, f"Welcome, {user['full_name']}!"


def logout_user():
    """Clear session and log the logout event."""
    username = st.session_state.get("username", "unknown")
    role = st.session_state.get("role", "")
    db.log_audit(username, role, "LOGOUT", details="User logged out")
    _clear_session()


def _clear_session():
    """Reset all session state variables."""
    st.session_state["authenticated"] = False
    st.session_state["username"] = None
    st.session_state["role"] = None
    st.session_state["full_name"] = None
    st.session_state["login_time"] = None
    st.session_state["last_activity"] = None


# ==========================================
# ACCESS CONTROL GUARDS
# ==========================================

def require_login() -> bool:
    """
    Guard function. Returns True if user is authenticated.
    Returns False if not (caller should stop rendering).
    """
    if not is_authenticated():
        st.warning("🔒 You must be logged in to access this page.")
        return False
    return True


def require_role(allowed_roles) -> bool:
    """
    Guard function. Checks if the current user has one of the allowed roles.
    allowed_roles can be a string or list of strings.
    Returns True if authorized, False if not.
    """
    if isinstance(allowed_roles, str):
        allowed_roles = [allowed_roles]

    if not is_authenticated():
        st.warning("🔒 Authentication required.")
        return False

    current_role = get_current_role()
    if current_role not in allowed_roles:
        st.markdown("""
        <div style='background: rgba(220, 38, 38, 0.15); border: 1px solid rgba(239, 68, 68, 0.4); 
                    border-radius: 12px; padding: 30px; text-align: center; margin: 40px auto; max-width: 500px;'>
            <h2 style='color: #f87171; margin-top: 0;'>🚫 Access Denied</h2>
            <p style='color: #cbd5e1;'>You do not have the required clearance level to access this module.</p>
            <p style='color: #64748b; font-size: 0.85rem;'>Required: <strong>{}</strong> | Your Role: <strong>{}</strong></p>
        </div>
        """.format(", ".join(allowed_roles).upper(), current_role.upper()), unsafe_allow_html=True)
        return False

    return True


def can_access_case(case_id: str) -> bool:
    """
    Fine-grained case-level authorization.
    - Admin: can access all cases
    - Officer: can access only assigned cases
    - Citizen: can access only their own submitted cases
    """
    if not is_authenticated():
        return False

    role = get_current_role()
    username = get_current_username()

    if role == "admin":
        return True

    if role == "officer":
        assigned = db.get_officer_assigned_cases(username)
        return case_id in assigned

    if role == "citizen":
        case = db.get_case_by_id(case_id)
        if case and case.get("submitted_by") == username:
            return True
        return False

    return False


# ==========================================
# AUDIT LOGGING HELPERS
# ==========================================

def audit_case_access(case_id: str):
    """Log when a user views a case."""
    db.log_audit(
        get_current_username(), get_current_role(),
        "CASE_VIEW", target_resource=case_id,
        details=f"Viewed case details"
    )


def audit_case_update(case_id: str, changes: str = ""):
    """Log when a user updates a case."""
    db.log_audit(
        get_current_username(), get_current_role(),
        "CASE_UPDATE", target_resource=case_id,
        details=changes
    )


def audit_evidence_access(case_id: str):
    """Log when a user views evidence for a case."""
    db.log_audit(
        get_current_username(), get_current_role(),
        "EVIDENCE_VIEW", target_resource=case_id,
        details="Accessed evidence records"
    )


def audit_user_created(new_username: str, new_role: str):
    """Log when an admin creates a new user."""
    db.log_audit(
        get_current_username(), get_current_role(),
        "USER_CREATED", target_resource=new_username,
        details=f"Created new {new_role} account"
    )


def audit_user_deleted(deleted_username: str):
    """Log when an admin deletes a user."""
    db.log_audit(
        get_current_username(), get_current_role(),
        "USER_DELETED", target_resource=deleted_username,
        details="Deleted user account"
    )
