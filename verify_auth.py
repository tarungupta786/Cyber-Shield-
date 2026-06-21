import os
import sys

from dotenv import load_dotenv
load_dotenv()


def test_password_hashing():
    print("\n[AUTH] Testing password hashing...")
    import auth

    hashed = auth.hash_password("TestPassword123!")
    if not hashed.startswith("$2b$"):
        print("FAIL: Hash doesn't look like bcrypt output")
        return False

    if not auth.check_password("TestPassword123!", hashed):
        print("FAIL: Correct password rejected")
        return False

    if auth.check_password("WrongPassword!!", hashed):
        print("FAIL: Wrong password accepted")
        return False

    print("SUCCESS: Password hashing and verification roundtrip works.")
    return True


def test_password_policy():
    print("\n[AUTH] Testing password policy...")
    import auth

    cases = [
        ("Short1!",         True,  "too short"),
        ("alllowercase1!!", True,  "no uppercase"),
        ("ALLUPPERCASE1!!", True,  "no lowercase"),
        ("NoDigitsHere!!!", True,  "no digit"),
        ("NoSpecial12345",  True,  "no special char"),
        ("GoodPass123!",    False, "valid password"),
    ]

    for pw, should_fail, label in cases:
        ok, _ = auth.validate_password(pw)
        if should_fail and ok:
            print(f"FAIL: Accepted {label}: '{pw}'")
            return False
        if not should_fail and not ok:
            print(f"FAIL: Rejected {label}: '{pw}'")
            return False

    print("SUCCESS: Password policy catches weak passwords, accepts strong ones.")
    return True


def test_username_validation():
    print("\n[AUTH] Testing username validation...")
    import auth

    ok, _ = auth.validate_username("ab")
    if ok:
        print("FAIL: Accepted 2-char username")
        return False

    ok, _ = auth.validate_username("valid.user_1")
    if not ok:
        print("FAIL: Rejected a valid username")
        return False

    ok, _ = auth.validate_username("has spaces!")
    if ok:
        print("FAIL: Accepted username with spaces")
        return False

    ok, _ = auth.validate_username("")
    if ok:
        print("FAIL: Accepted empty username")
        return False

    print("SUCCESS: Username validation works.")
    return True


def test_jwt_tokens():
    print("\n[AUTH] Testing JWT access tokens...")
    import auth

    token = auth.create_access_token(1, "testuser", "citizen")
    payload = auth.verify_access_token(token)

    if not payload:
        print("FAIL: Fresh token didn't verify")
        return False
    if payload["username"] != "testuser" or payload["role"] != "citizen":
        print("FAIL: Payload contents don't match")
        return False
    if payload.get("type") != "access":
        print("FAIL: Token type should be 'access'")
        return False

    bad = auth.verify_access_token("definitely.not.a.jwt")
    if bad is not None:
        print("FAIL: Garbage token shouldn't verify")
        return False

    print("SUCCESS: JWT access token creation and verification work.")
    return True


def test_refresh_rotation():
    print("\n[AUTH] Testing refresh token rotation + reuse detection...")
    import auth
    import auth_db
    import database as db

    user = db.get_user_by_username("admin")
    if not user:
        print("FAIL: No 'admin' user found. Run the app first to seed data.")
        return False

    uid = user["id"]

    raw_a, jti_a = auth.create_refresh_token(uid)

    # First rotation should succeed
    result = auth.rotate_refresh_token(raw_a)
    if result is None:
        print("FAIL: First rotation returned None")
        return False

    new_access, raw_b, _ = result

    # Old token should be marked replaced
    old = auth_db.get_refresh_token(jti_a)
    if not old["revoked"] or not old["replaced_by"]:
        print("FAIL: Old token not properly marked as replaced")
        return False

    # Replaying the old token should trigger reuse detection
    reuse = auth.rotate_refresh_token(raw_a)
    if reuse is not None:
        print("FAIL: Reuse of already-rotated token should fail")
        return False

    # The replacement token should also be revoked now (nuclear option)
    new_jti = old["replaced_by"]
    new_record = auth_db.get_refresh_token(new_jti)
    if new_record and not new_record["revoked"]:
        print("FAIL: Reuse detection should have revoked the replacement token too")
        return False

    print("SUCCESS: Refresh token rotation and reuse detection work.")
    return True


def test_lockout():
    print("\n[AUTH] Testing account lockout after failed attempts...")
    import auth
    import database as db

    test_user = "_lockout_test_tmp"
    if not db.get_user_by_username(test_user):
        hashed = auth.hash_password("TestLock01!")
        db.create_user(test_user, hashed, "citizen", "Lockout Tester")

    for i in range(5):
        ok, _, _, _ = auth.login(test_user, "wrongpassword")
        if ok:
            print("FAIL: Wrong password shouldn't succeed")
            db.delete_user(test_user)
            return False

    ok, msg, _, _ = auth.login(test_user, "wrongpassword")
    if ok:
        print("FAIL: 6th attempt should report lockout")
        db.delete_user(test_user)
        return False

    if "locked" not in msg.lower():
        print(f"FAIL: Expected lockout message, got: {msg}")
        db.delete_user(test_user)
        return False

    # Even correct password should fail while locked
    ok, _, _, _ = auth.login(test_user, "TestLock01!")
    if ok:
        print("FAIL: Correct password should still be rejected during lockout")
        db.delete_user(test_user)
        return False

    db.delete_user(test_user)
    print("SUCCESS: Account locks out after 5 failed attempts.")
    return True


def test_role_access():
    print("\n[AUTH] Testing role-based access control...")
    import auth
    import streamlit as st

    # Simulate a citizen session
    st.session_state["authenticated"] = True
    st.session_state["username"] = "_test_citizen"
    st.session_state["role"] = "citizen"

    if auth.get_current_role() != "citizen":
        print("FAIL: Expected citizen role")
        auth._clear_session()
        return False

    # Citizen shouldn't access a case they didn't submit
    if auth.can_access_case("CS-2026-0001"):
        print("FAIL: Citizen shouldn't access unowned case")
        auth._clear_session()
        return False

    # Simulate admin
    st.session_state["role"] = "admin"
    if not auth.can_access_case("CS-2026-0001"):
        print("FAIL: Admin should access any case")
        auth._clear_session()
        return False

    auth._clear_session()
    print("SUCCESS: Role-based access works for citizen and admin.")
    return True


if __name__ == "__main__":
    results = [
        test_password_hashing(),
        test_password_policy(),
        test_username_validation(),
        test_jwt_tokens(),
        test_refresh_rotation(),
        test_lockout(),
        test_role_access(),
    ]

    if all(results):
        print("\nALL AUTH TESTS PASSED!")
    else:
        print("\nSOME TESTS FAILED.")
        sys.exit(1)
