import os
import uuid
import streamlit as st
from streamlit_cookies_controller import CookieController

import auth
import auth_db
import database as db

REFRESH_COOKIE = "cybershield_refresh"
COOKIE_MAX_AGE = 7 * 24 * 3600

_ctl = None


def _cookies():
    global _ctl
    if _ctl is None:
        _ctl = CookieController()
    return _ctl


def check_session():
    """
    Call at the top of every page. Validates the access token in session
    state; if it's expired or missing, tries a silent refresh using the
    cookie before giving up and forcing re-login.
    """
    auth.init_session()
    cookies = _cookies()

    token = st.session_state.get("access_token")
    if token:
        payload = auth.verify_access_token(token)
        if payload:
            return

    # Access token gone or expired -- try the refresh cookie
    refresh = cookies.get(REFRESH_COOKIE)
    if not refresh:
        auth._clear_session()
        return

    result = auth.rotate_refresh_token(refresh)
    if result is None:
        cookies.remove(REFRESH_COOKIE)
        auth._clear_session()
        return

    new_access, new_refresh, user = result
    auth._set_session(user, new_access)

    # Streamlit can't set true HttpOnly cookies from Python -- the cookie
    # library works via client-side JS. Best we can do: Secure + SameSite.
    # The access token (the sensitive part) never touches a cookie; it stays
    # in st.session_state on the server side only.
    _set_refresh_cookie(new_refresh)


def _set_refresh_cookie(token):
    is_prod = os.environ.get("ENVIRONMENT", "dev") == "prod"
    try:
        _cookies().set(REFRESH_COOKIE, token, max_age=COOKIE_MAX_AGE,
                       secure=is_prod, same_site="Strict")
    except TypeError:
        _cookies().set(REFRESH_COOKIE, token)


def handle_logout():
    cookies = _cookies()
    refresh = cookies.get(REFRESH_COOKIE)
    if refresh:
        auth.revoke_refresh(refresh)
        cookies.remove(REFRESH_COOKIE)
    auth.logout_user()


def handle_logout_all():
    uid = st.session_state.get("user_id")
    if uid:
        auth.logout_all_devices(uid)
    cookies = _cookies()
    cookies.remove(REFRESH_COOKIE)
    auth.logout_user()


def _gen_nonce(key="auth_nonce"):
    n = str(uuid.uuid4())
    st.session_state[key] = n
    return n


def _consume_nonce(key="auth_nonce"):
    # Streamlit sessions are tied to websocket connections, so cross-origin
    # form posting isn't really a thing here. This nonce is a lightweight
    # replay guard, not full CSRF defense.
    val = st.session_state.get(key)
    if not val:
        return False
    st.session_state[key] = None
    return True


def render_auth_page():
    st.markdown("""

    <div class='login-container'>
        <div class='login-header'>
            <div class='hero-shield-wrapper'>
                <div class='hero-shield-glow'></div>
                <div class='hero-shield-icon'></div>
            </div>
            <h1 class='hero-title-animated'>Cyber<span class="accent-text">Shield</span></h1>
            <p class='hero-tagline-animated'>Advanced Threat Intelligence & Cyber Defense</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

    tab_login, tab_register = st.tabs(["Login", "Register"])

    with tab_login:
        _render_login_form()

    with tab_register:
        _render_register_form()

    st.markdown("""
    <div class="trust-indicators">
        <span>AI-Powered Detection</span>
        <span>IPC & IT Act Compliant</span>
        <span>Real-Time Threat Analysis</span>
    </div>
    """, unsafe_allow_html=True)


def _render_login_form():
    if not st.session_state.get("auth_nonce"):
        _gen_nonce("auth_nonce")

    col1, col_form, col2 = st.columns([1, 2, 1])
    with col_form:
        with st.form("login_form"):
            username = st.text_input("Username", placeholder="Enter your username")
            password = st.text_input("Password", type="password",
                                     placeholder="Enter your password")
            submitted = st.form_submit_button("Secure Login", type="primary",
                                              use_container_width=True)

        if submitted:
            if not _consume_nonce("auth_nonce"):
                _gen_nonce("auth_nonce")
                st.error("Session expired. Please try again.")
                return

            ok, msg, access, refresh = auth.login(username, password)
            if ok:
                user = db.get_user_by_username(username.strip().lower())
                auth._set_session(user, access)
                _set_refresh_cookie(refresh)
                _gen_nonce("auth_nonce")
                st.rerun()
            else:
                _gen_nonce("auth_nonce")
                st.markdown(f"<div class='login-error'>{msg}</div>",
                            unsafe_allow_html=True)

        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown(
            "<p style='text-align:center; color:#64748b; font-size:0.8rem;'>"
            "Default Admin: <code>admin</code> / <code>CyberShield@2026</code><br>"
            "Default Officer: <code>insp.vikram</code> / <code>Officer@2026</code></p>",
            unsafe_allow_html=True
        )


def _render_register_form():
    if not st.session_state.get("reg_nonce"):
        _gen_nonce("reg_nonce")

    col1, col_form, col2 = st.columns([1, 2, 1])
    with col_form:
        with st.form("register_form"):
            new_user = st.text_input("Username", placeholder="e.g. rahul.kumar")
            full_name = st.text_input("Full Name", placeholder="e.g. Rahul Kumar")
            role = st.selectbox("I am a", ["citizen", "officer"])
            badge = st.text_input("Badge Number (officers only)",
                                  placeholder="e.g. IPS-1234")
            pw = st.text_input("Password", type="password",
                               placeholder="Min 10 chars, mixed case, digit, special")
            pw_confirm = st.text_input("Confirm Password", type="password")
            submitted = st.form_submit_button("Create Account", type="primary",
                                              use_container_width=True)

        if submitted:
            if not _consume_nonce("reg_nonce"):
                _gen_nonce("reg_nonce")
                st.error("Session expired. Try again.")
                return

            # server-side validation
            ok, msg = auth.validate_username(new_user)
            if not ok:
                st.error(msg)
                _gen_nonce("reg_nonce")
                return

            if not full_name or len(full_name.strip()) < 2:
                st.error("Full name is required.")
                _gen_nonce("reg_nonce")
                return

            ok, msg = auth.validate_password(pw)
            if not ok:
                st.error(msg)
                _gen_nonce("reg_nonce")
                return

            if pw != pw_confirm:
                st.error("Passwords don't match.")
                _gen_nonce("reg_nonce")
                return

            clean = new_user.strip().lower()
            if db.get_user_by_username(clean):
                st.error("Username already taken.")
                _gen_nonce("reg_nonce")
                return

            hashed = auth.hash_password(pw)
            db.create_user(clean, hashed, role, full_name.strip(), badge)

            user = db.get_user_by_username(clean)
            auth_db.log_auth_event(
                user["id"], clean, "REGISTRATION",
                details=f"New {role} account created"
            )

            st.success(f"Account created! You can now log in as '{clean}'.")
            _gen_nonce("reg_nonce")
