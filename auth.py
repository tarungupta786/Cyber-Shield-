import os
import re
import uuid
import hashlib
import bcrypt
import jwt
import streamlit as st
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

import database as db
import auth_db

ACCESS_EXPIRY = timedelta(minutes=15)
REFRESH_EXPIRY = timedelta(days=7)

_priv_key = None
_pub_key = None


def _ensure_keys():
    global _priv_key, _pub_key
    if _priv_key and _pub_key:
        return

    priv_path = os.environ.get("PRIVATE_KEY_PATH", "keys/private.pem")
    pub_path = os.environ.get("PUBLIC_KEY_PATH", "keys/public.pem")

    if not os.path.exists(priv_path) or not os.path.exists(pub_path):
        if os.environ.get("ENVIRONMENT", "dev") == "prod":
            raise RuntimeError(
                f"RSA keys missing ({priv_path}, {pub_path}). "
                "Generate them before running in production."
            )
        _gen_rsa_keys(priv_path, pub_path)

    with open(priv_path, "rb") as f:
        _priv_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(pub_path, "rb") as f:
        _pub_key = serialization.load_pem_public_key(f.read())


def _gen_rsa_keys(priv_path, pub_path):
    for p in (priv_path, pub_path):
        d = os.path.dirname(p)
        if d:
            os.makedirs(d, exist_ok=True)

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    with open(priv_path, "wb") as f:
        f.write(private.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()
        ))
    with open(pub_path, "wb") as f:
        f.write(private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    print(f"Generated RSA keypair at {priv_path} and {pub_path}")


def hash_password(plain):
    return bcrypt.hashpw(
        plain.encode("utf-8"), bcrypt.gensalt(rounds=12)
    ).decode("utf-8")


def check_password(plain, hashed):
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def validate_password(pw):
    if len(pw) < 10:
        return False, "Password must be at least 10 characters."
    if not re.search(r"[A-Z]", pw):
        return False, "Needs at least one uppercase letter."
    if not re.search(r"[a-z]", pw):
        return False, "Needs at least one lowercase letter."
    if not re.search(r"\d", pw):
        return False, "Needs at least one digit."
    if not re.search(r"[^A-Za-z0-9]", pw):
        return False, "Needs at least one special character."
    return True, ""


def validate_username(name):
    if not name or len(name) < 3 or len(name) > 30:
        return False, "Username must be between 3 and 30 characters."
    if not re.match(r"^[a-zA-Z0-9._]+$", name):
        return False, "Only letters, numbers, dots, and underscores allowed."
    return True, ""


def create_access_token(user_id, username, role):
    _ensure_keys()
    now = datetime.now(timezone.utc)
    return jwt.encode({
        "sub": str(user_id),
        "username": username,
        "role": role,
        "iat": now,
        "exp": now + ACCESS_EXPIRY,
        "jti": str(uuid.uuid4()),
        "type": "access",
    }, _priv_key, algorithm="RS256")


def verify_access_token(token):
    """Returns decoded payload, or None if invalid/expired/revoked."""
    _ensure_keys()
    try:
        payload = jwt.decode(token, _pub_key, algorithms=["RS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

    if payload.get("type") != "access":
        return None

    # If this user's sessions were bulk-revoked (e.g. token reuse detected),
    # reject any access token issued before the revocation timestamp.
    revoked_at = auth_db.get_sessions_revoked_at(int(payload["sub"]))
    if revoked_at:
        issued = datetime.fromtimestamp(payload["iat"])
        if issued < revoked_at:
            return None

    return payload


def create_refresh_token(user_id):
    _ensure_keys()
    jti = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    exp = now + REFRESH_EXPIRY

    raw = jwt.encode({
        "sub": str(user_id),
        "jti": jti,
        "iat": now,
        "exp": exp,
        "type": "refresh",
    }, _priv_key, algorithm="RS256")

    token_hash = hashlib.sha256(raw.encode()).hexdigest()
    auth_db.store_refresh_token(
        jti, user_id, token_hash, exp.strftime("%Y-%m-%d %H:%M:%S")
    )
    return raw, jti


def rotate_refresh_token(raw_token):
    """
    Swap an existing refresh token for fresh access + refresh tokens.

    Reuse detection: if the presented token was already rotated out
    (replaced_by is set), someone is replaying a stolen token. In that
    case, revoke every session for that user as a precaution.

    Returns (new_access, new_refresh, user_dict) or None on failure.
    """
    _ensure_keys()
    try:
        payload = jwt.decode(raw_token, _pub_key, algorithms=["RS256"])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

    if payload.get("type") != "refresh":
        return None

    jti = payload["jti"]
    user_id = int(payload["sub"])
    stored = auth_db.get_refresh_token(jti)

    if not stored:
        return None

    # Already swapped for a newer token? That's a replay.
    if stored["replaced_by"] is not None:
        auth_db.revoke_all_user_tokens(user_id)
        auth_db.set_sessions_revoked(user_id)
        auth_db.log_auth_event(
            user_id, "", "TOKEN_REUSE",
            details=f"Revoked all sessions, replayed jti: {jti}"
        )
        return None

    if stored["revoked"]:
        return None

    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    if token_hash != stored["token_hash"]:
        return None

    user = auth_db.get_user_by_id(user_id)
    if not user or not user.get("is_active", 1):
        return None

    new_access = create_access_token(user["id"], user["username"], user["role"])
    new_refresh, new_jti = create_refresh_token(user_id)
    auth_db.mark_replaced(jti, new_jti)

    return new_access, new_refresh, user


def revoke_refresh(raw_token):
    _ensure_keys()
    try:
        payload = jwt.decode(
            raw_token, _pub_key, algorithms=["RS256"],
            options={"verify_exp": False}
        )
    except jwt.InvalidTokenError:
        return
    jti = payload.get("jti")
    if jti:
        auth_db.revoke_token(jti)


def logout_all_devices(user_id):
    auth_db.revoke_all_user_tokens(user_id)
    auth_db.set_sessions_revoked(user_id)
    auth_db.log_auth_event(user_id, "", "LOGOUT_ALL_DEVICES")


def login(username, password):
    """Returns (success, message, access_token, refresh_token)."""
    if not username or not password:
        return False, "Enter both username and password.", None, None

    username = username.strip().lower()
    user = db.get_user_by_username(username)

    if not user:
        return False, "Invalid credentials.", None, None

    if not user.get("is_active", 1):
        return False, "Account deactivated. Contact an administrator.", None, None

    is_locked, failed_count, lock_until = db.is_account_locked(username)
    if is_locked:
        remaining = max(1, (lock_until - datetime.now()).seconds // 60)
        auth_db.log_auth_event(user["id"], username, "LOGIN_BLOCKED")
        return False, f"Account locked. Try again in {remaining} minutes.", None, None

    if not check_password(password, user["password_hash"]):
        db.increment_failed_attempts(username)
        left = 5 - (failed_count + 1)
        auth_db.log_auth_event(user["id"], username, "LOGIN_FAILED")
        if left <= 0:
            return False, "Account locked for 15 minutes.", None, None
        return False, f"Invalid credentials. {left} attempt(s) remaining.", None, None

    db.update_user_login(username)
    access = create_access_token(user["id"], username, user["role"])
    refresh, _ = create_refresh_token(user["id"])

    auth_db.log_auth_event(user["id"], username, "LOGIN_SUCCESS")
    db.log_audit(username, user["role"], "LOGIN_SUCCESS", details="JWT auth")

    return True, f"Welcome, {user['full_name']}!", access, refresh


# --- session state (preserves the API that app.py already uses) ---

def init_session():
    defaults = {
        "authenticated": False,
        "username": None,
        "role": None,
        "full_name": None,
        "user_id": None,
        "access_token": None,
        "login_time": None,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v


def _set_session(user, access_token):
    st.session_state["authenticated"] = True
    st.session_state["username"] = user["username"]
    st.session_state["role"] = user["role"]
    st.session_state["full_name"] = user["full_name"]
    st.session_state["user_id"] = user["id"]
    st.session_state["access_token"] = access_token
    st.session_state["login_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _clear_session():
    for k in ["username", "role", "full_name", "user_id", "access_token", "login_time"]:
        st.session_state[k] = None
    st.session_state["authenticated"] = False


def is_authenticated():
    return st.session_state.get("authenticated", False)


def get_current_user():
    return {
        "username": st.session_state.get("username"),
        "role": st.session_state.get("role"),
        "full_name": st.session_state.get("full_name"),
        "login_time": st.session_state.get("login_time"),
    }


def get_current_role():
    return st.session_state.get("role", "")


def get_current_username():
    return st.session_state.get("username", "")


def require_login():
    if not is_authenticated():
        st.warning("You must be logged in to access this page.")
        return False
    return True


def require_role(allowed_roles):
    if isinstance(allowed_roles, str):
        allowed_roles = [allowed_roles]

    if not is_authenticated():
        st.warning("Authentication required.")
        return False

    current = get_current_role()
    if current not in allowed_roles:
        st.markdown("""
        <div style='background: rgba(220, 38, 38, 0.15); border: 1px solid rgba(239, 68, 68, 0.4);
                    border-radius: 12px; padding: 30px; text-align: center; margin: 40px auto; max-width: 500px;'>
            <h2 style='color: #f87171; margin-top: 0;'>Access Denied</h2>
            <p style='color: #cbd5e1;'>You do not have the required clearance level.</p>
            <p style='color: #64748b; font-size: 0.85rem;'>Required: <strong>{}</strong> | Your Role: <strong>{}</strong></p>
        </div>
        """.format(", ".join(allowed_roles).upper(), current.upper()), unsafe_allow_html=True)
        return False

    return True


def can_access_case(case_id):
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
        return case and case.get("submitted_by") == username
    return False


# --- audit helpers (used throughout app.py, keeping same interface) ---

def audit_case_access(case_id):
    db.log_audit(
        get_current_username(), get_current_role(),
        "CASE_VIEW", target_resource=case_id,
        details="Viewed case details"
    )

def audit_case_update(case_id, changes=""):
    db.log_audit(
        get_current_username(), get_current_role(),
        "CASE_UPDATE", target_resource=case_id,
        details=changes
    )

def audit_evidence_access(case_id):
    db.log_audit(
        get_current_username(), get_current_role(),
        "EVIDENCE_VIEW", target_resource=case_id,
        details="Accessed evidence records"
    )

def audit_user_created(new_username, new_role):
    db.log_audit(
        get_current_username(), get_current_role(),
        "USER_CREATED", target_resource=new_username,
        details=f"Created new {new_role} account"
    )

def audit_user_deleted(deleted_username):
    db.log_audit(
        get_current_username(), get_current_role(),
        "USER_DELETED", target_resource=deleted_username,
        details="Deleted user account"
    )


def logout_user():
    username = st.session_state.get("username", "unknown")
    role = st.session_state.get("role", "")
    uid = st.session_state.get("user_id")
    db.log_audit(username, role, "LOGOUT", details="User logged out")
    if uid:
        auth_db.log_auth_event(uid, username, "LOGOUT")
    _clear_session()
