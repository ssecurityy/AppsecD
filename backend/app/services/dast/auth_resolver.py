"""Grey-box authentication resolver for DAST scanning.

Resolves auth configs into headers/cookies that can be injected into all HTTP requests
during authenticated scanning. Supports bearer, cookie, basic, api_key, custom_header,
form_login (with optional TOTP/MFA), and OAuth2 flows.
"""
import base64
import logging
import time
from typing import Optional

import httpx

logger = logging.getLogger(__name__)

# Auth config types
AUTH_TYPES = ["bearer", "cookie", "basic", "api_key", "custom_header", "form_login", "oauth2"]


async def resolve_auth(auth_config: dict) -> dict:
    """Resolve an auth_config into usable headers and cookies.

    Returns: {"headers": {...}, "cookies": {...}, "auth_type": str, "expires_at": int|None}
    """
    if not auth_config:
        return {"headers": {}, "cookies": {}, "auth_type": "none", "expires_at": None}

    auth_type = auth_config.get("type", "").lower()

    try:
        if auth_type == "bearer":
            return _resolve_bearer(auth_config)
        elif auth_type == "cookie":
            return _resolve_cookie(auth_config)
        elif auth_type == "basic":
            return _resolve_basic(auth_config)
        elif auth_type == "api_key":
            return _resolve_api_key(auth_config)
        elif auth_type == "custom_header":
            return _resolve_custom_header(auth_config)
        elif auth_type == "form_login":
            return await _resolve_form_login(auth_config)
        elif auth_type == "oauth2":
            return await _resolve_oauth2(auth_config)
        else:
            logger.warning("Unknown auth type: %s", auth_type)
            return {"headers": {}, "cookies": {}, "auth_type": "unknown", "expires_at": None}
    except Exception as e:
        logger.error("Auth resolution failed for type %s: %s", auth_type, e)
        return {"headers": {}, "cookies": {}, "auth_type": auth_type, "error": str(e), "expires_at": None}


def _resolve_bearer(config: dict) -> dict:
    """Resolve bearer token auth."""
    token = config.get("token", "")
    return {
        "headers": {"Authorization": f"Bearer {token}"},
        "cookies": {},
        "auth_type": "bearer",
        "expires_at": None,
    }


def _resolve_cookie(config: dict) -> dict:
    """Resolve cookie-based auth."""
    cookie_string = config.get("cookie_string", "")
    cookies = {}
    for part in cookie_string.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return {
        "headers": {"Cookie": cookie_string},
        "cookies": cookies,
        "auth_type": "cookie",
        "expires_at": None,
    }


def _resolve_basic(config: dict) -> dict:
    """Resolve HTTP Basic auth."""
    username = config.get("username", "")
    password = config.get("password", "")
    encoded = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {
        "headers": {"Authorization": f"Basic {encoded}"},
        "cookies": {},
        "auth_type": "basic",
        "expires_at": None,
    }


def _resolve_api_key(config: dict) -> dict:
    """Resolve API key auth (in header or query param)."""
    token = config.get("token", "")
    header_name = config.get("header_name", "X-API-Key")
    return {
        "headers": {header_name: token},
        "cookies": {},
        "auth_type": "api_key",
        "expires_at": None,
    }


def _resolve_custom_header(config: dict) -> dict:
    """Resolve custom header auth."""
    headers = config.get("headers", {})
    return {
        "headers": headers,
        "cookies": {},
        "auth_type": "custom_header",
        "expires_at": None,
    }


async def _resolve_form_login(config: dict) -> dict:
    """Perform form login, optionally with TOTP, and capture session tokens."""
    login_url = config.get("login_url", "")
    login_body = config.get("login_body", {})
    username = config.get("username", "")
    password = config.get("password", "")
    totp_secret = config.get("totp_secret")
    mfa_type = config.get("mfa_type", "totp")

    if not login_body:
        login_body = {
            config.get("username_field", "username"): username,
            config.get("password_field", "password"): password,
        }

    # Add TOTP code if secret provided
    if totp_secret and mfa_type == "totp":
        code = generate_totp(totp_secret)
        login_body[config.get("totp_field", "totp_code")] = code

    headers = {}
    cookies = {}
    expires_at = None

    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0), verify=False, follow_redirects=False) as client:
        try:
            content_type = config.get("content_type", "application/json")
            if content_type == "application/x-www-form-urlencoded":
                resp = await client.post(login_url, data=login_body)
            else:
                resp = await client.post(login_url, json=login_body)

            # Extract auth tokens from response
            # 1. Check Set-Cookie headers
            for cookie_header in resp.headers.get_list("set-cookie"):
                parts = cookie_header.split(";")
                if parts:
                    kv = parts[0].strip()
                    if "=" in kv:
                        k, v = kv.split("=", 1)
                        cookies[k.strip()] = v.strip()

            # 2. Check response body for tokens
            try:
                body = resp.json()
                for key in ["token", "access_token", "jwt", "session_token", "auth_token", "id_token"]:
                    if key in body:
                        headers["Authorization"] = f"Bearer {body[key]}"
                        break
                # Check for expiry
                if "expires_in" in body:
                    expires_at = int(time.time()) + int(body["expires_in"])
            except Exception:
                pass

            # 3. Build cookie header
            if cookies:
                cookie_str = "; ".join(f"{k}={v}" for k, v in cookies.items())
                headers["Cookie"] = cookie_str

            # Handle MFA step if needed
            if totp_secret and resp.status_code in (200, 302) and not headers.get("Authorization"):
                mfa_url = config.get("mfa_url", "")
                if mfa_url:
                    code = generate_totp(totp_secret)
                    mfa_body = {config.get("totp_field", "code"): code}
                    if config.get("mfa_token_field"):
                        try:
                            mfa_body[config["mfa_token_field"]] = resp.json().get(config["mfa_token_field"], "")
                        except Exception:
                            pass
                    mfa_resp = await client.post(mfa_url, json=mfa_body, headers=headers, cookies=cookies)
                    # Extract tokens from MFA response
                    for cookie_header in mfa_resp.headers.get_list("set-cookie"):
                        parts = cookie_header.split(";")
                        if parts:
                            kv = parts[0].strip()
                            if "=" in kv:
                                k, v = kv.split("=", 1)
                                cookies[k.strip()] = v.strip()
                    try:
                        mfa_body_resp = mfa_resp.json()
                        for key in ["token", "access_token", "jwt", "session_token"]:
                            if key in mfa_body_resp:
                                headers["Authorization"] = f"Bearer {mfa_body_resp[key]}"
                                break
                    except Exception:
                        pass
                    if cookies:
                        headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in cookies.items())

            logger.info("Form login completed: %d headers, %d cookies captured", len(headers), len(cookies))
        except Exception as e:
            logger.error("Form login failed: %s", e)
            return {"headers": {}, "cookies": {}, "auth_type": "form_login", "error": str(e), "expires_at": None}

    return {
        "headers": headers,
        "cookies": cookies,
        "auth_type": "form_login",
        "expires_at": expires_at,
    }


async def _resolve_oauth2(config: dict) -> dict:
    """Perform OAuth2 token exchange."""
    oauth_config = config.get("oauth2_config", {})
    token_url = oauth_config.get("token_url", "")
    client_id = oauth_config.get("client_id", "")
    client_secret = oauth_config.get("client_secret", "")
    scope = oauth_config.get("scope", "")
    grant_type = oauth_config.get("grant_type", "client_credentials")

    body = {
        "grant_type": grant_type,
        "client_id": client_id,
        "client_secret": client_secret,
    }
    if scope:
        body["scope"] = scope

    # For password grant
    if grant_type == "password":
        body["username"] = config.get("username", "")
        body["password"] = config.get("password", "")

    expires_at = None
    async with httpx.AsyncClient(timeout=httpx.Timeout(30.0), verify=False) as client:
        try:
            resp = await client.post(token_url, data=body)
            token_data = resp.json()
            access_token = token_data.get("access_token", "")
            token_type = token_data.get("token_type", "Bearer")
            if "expires_in" in token_data:
                expires_at = int(time.time()) + int(token_data["expires_in"])

            logger.info("OAuth2 token obtained: type=%s, expires_in=%s", token_type, token_data.get("expires_in"))
            return {
                "headers": {"Authorization": f"{token_type} {access_token}"},
                "cookies": {},
                "auth_type": "oauth2",
                "expires_at": expires_at,
                "refresh_token": token_data.get("refresh_token"),
            }
        except Exception as e:
            logger.error("OAuth2 flow failed: %s", e)
            return {"headers": {}, "cookies": {}, "auth_type": "oauth2", "error": str(e), "expires_at": None}


def generate_totp(secret: str) -> str:
    """Generate current TOTP code from base32 secret."""
    try:
        import pyotp
        totp = pyotp.TOTP(secret)
        return totp.now()
    except ImportError:
        logger.error("pyotp not installed — cannot generate TOTP codes")
        return ""
    except Exception as e:
        logger.error("TOTP generation failed: %s", e)
        return ""


async def refresh_auth(auth_config: dict, current_auth: dict) -> dict:
    """Re-authenticate if the current auth has expired."""
    expires_at = current_auth.get("expires_at")
    if expires_at and time.time() < expires_at - 60:
        # Still valid (with 60s buffer)
        return current_auth

    # Try refresh token for OAuth2
    if current_auth.get("auth_type") == "oauth2" and current_auth.get("refresh_token"):
        oauth_config = auth_config.get("oauth2_config", {})
        token_url = oauth_config.get("token_url", "")
        async with httpx.AsyncClient(timeout=httpx.Timeout(30.0), verify=False) as client:
            try:
                resp = await client.post(token_url, data={
                    "grant_type": "refresh_token",
                    "refresh_token": current_auth["refresh_token"],
                    "client_id": oauth_config.get("client_id", ""),
                    "client_secret": oauth_config.get("client_secret", ""),
                })
                token_data = resp.json()
                new_expires = None
                if "expires_in" in token_data:
                    new_expires = int(time.time()) + int(token_data["expires_in"])
                return {
                    "headers": {"Authorization": f"Bearer {token_data['access_token']}"},
                    "cookies": current_auth.get("cookies", {}),
                    "auth_type": "oauth2",
                    "expires_at": new_expires,
                    "refresh_token": token_data.get("refresh_token", current_auth.get("refresh_token")),
                }
            except Exception as e:
                logger.warning("Token refresh failed, re-authenticating: %s", e)

    # Fall back to full re-authentication
    return await resolve_auth(auth_config)
