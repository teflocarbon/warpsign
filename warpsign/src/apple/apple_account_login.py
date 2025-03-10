import base64
import hashlib
import json
import os
from pathlib import Path
import srp
import requests
import getpass
import http.cookiejar as cookielib
import re
from typing import Optional
from datetime import datetime, timezone
from warpsign.logger import get_console
from warpsign.src.utils.config_loader import get_session_dir, get_apple_credentials

console = get_console()


class LoggingCookieJar(cookielib.LWPCookieJar):
    def set_cookie(self, cookie):
        expires = (
            "never"
            if cookie.expires is None
            else f"expires {datetime.fromtimestamp(cookie.expires, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC"
        )
        return super().set_cookie(cookie)


class AppleDeveloperAuth:
    """Minimal tester using iCloud's SRP implementation"""

    def __init__(self):
        self.session = requests.Session()
        self.auth_endpoint = "https://idmsa.apple.com/appleauth/auth"
        self._widget_key = None
        self.csrf = None
        self.csrf_ts = None
        self.email = None  # Store email for session management
        self.session_data = {}  # Initialize empty session data

        # Check for custom session directory from environment or config
        session_dir = get_session_dir()
        self._cookie_directory = session_dir

        self._cookie_directory.mkdir(parents=True, exist_ok=True)

    def _get_session_id(self, email: str) -> str:
        """Generate consistent session ID from email"""
        # Use first 8 chars of email hash for ID
        return f"auth-{hashlib.sha256(email.encode()).hexdigest()[:8]}"

    def _get_paths(self, email: str) -> tuple[str, str]:
        """Get cookie and session paths for email"""
        session_id = self._get_session_id(email)
        cookie_path = str(self._cookie_directory / f"{session_id}.cookies")
        session_path = str(self._cookie_directory / f"{session_id}.session")
        return cookie_path, session_path

    @property
    def widget_key(self) -> str:
        if not self._widget_key:
            response = self.session.get(
                "https://appstoreconnect.apple.com/olympus/v1/app/config?hostname=itunesconnect.apple.com"
            )
            self._widget_key = response.json().get("authServiceKey", "")
        return self._widget_key

    @property
    def cookiejar_path(self) -> str:
        """Get path for cookiejar file."""
        if not self.email:
            raise ValueError("Email not set")
        return self._get_paths(self.email)[0]

    @property
    def session_path(self) -> str:
        """Get path for session data file."""
        if not self.email:
            raise ValueError("Email not set")
        return self._get_paths(self.email)[1]

    def load_session(self) -> bool:
        """Load session data from file."""
        try:
            with open(self.session_path) as f:
                self.session_data = json.load(f)
                # Try to load cookies if they exist
                cookie_path = self._get_paths(self.email)[0]
                if os.path.exists(cookie_path):
                    self.session.cookies = LoggingCookieJar(filename=cookie_path)
                    self.session.cookies.load(ignore_discard=True, ignore_expires=True)
                return True
        except Exception as e:
            console.print(f"[yellow]Failed to load session: {e}")
            self.session_data = {}
            return False

    def save_session(self) -> None:
        """Save session data to file."""
        console.print("Saving session to", self.session_path)
        # Don't print sensitive session data
        console.print("Session data: [dim](sensitive data hidden)[/]")
        with open(self.session_path, "w") as f:
            json.dump(self.session_data, f)
        # Save ALL cookies, even if they're marked as discardable or expired
        self.session.cookies.save(ignore_discard=True, ignore_expires=True)
        console.print("[green]Session saved successfully[/]")

    def check_auth_status(self) -> bool:
        """Check authentication status using certificates endpoint."""
        if not self.session_data.get("session_id") or not self.session_data.get("scnt"):
            console.print("No session data found")
            return False

        try:
            headers = {
                "Accept": "application/json, text/plain, */*",
                "Content-Type": "application/vnd.api+json",
                "X-Requested-With": "XMLHttpRequest",
                "X-Apple-ID-Session-Id": self.session_data["session_id"],
                "scnt": self.session_data["scnt"],
            }

            response = self.session.get(
                "https://developer.apple.com/services-account/v1/certificates",
                headers=headers,
            )
            console.print("Auth status check response:", response.status_code)

            if response.status_code == 403:
                console.print("Session is valid")
                return True
            else:
                console.print("Session is invalid")
                return False
        except Exception as e:
            console.print(f"Auth status check failed: {str(e)}")
            return False

    def _get_cookie_value(self, name: str) -> Optional[str]:
        """Get cookie value by name"""
        for cookie in self.session.cookies:
            if cookie.name == name:
                return cookie.value
        return None

    def validate_token(self) -> bool:
        """Check if current session token is still valid and fetch CSRF tokens."""
        self._log_cookies("Using these cookies for validation:")
        if self.check_auth_status():
            # Fetch CSRF tokens after confirming session is valid
            response = self.session.get("https://developer.apple.com/account/resources")
            if response.status_code == 200:
                # Try cookies first
                self.csrf = self._get_cookie_value("csrf")
                self.csrf_ts = self._get_cookie_value("csrf_ts")

                # If not in cookies, try response headers
                if not self.csrf:
                    self.csrf = response.headers.get("csrf")
                if not self.csrf_ts:
                    self.csrf_ts = response.headers.get("csrf_ts")

                # If still not found, try to extract from page content
                if not self.csrf or not self.csrf_ts:
                    match = re.search(
                        r'csrf["\']\s*:\s*["\']([^"\']+)["\']', response.text
                    )
                    if match:
                        self.csrf = match.group(1)
                    match = re.search(
                        r'csrf_ts["\']\s*:\s*["\']([^"\']+)["\']', response.text
                    )
                    if match:
                        self.csrf_ts = match.group(1)

                if self.csrf and self.csrf_ts:
                    console.print("[green]Successfully retrieved CSRF tokens[/]")
                    console.print("[dim]CSRF: " + str(self.csrf) + "[/]")
                    console.print("[dim]CSRF_TS: " + str(self.csrf_ts) + "[/]")
                    return True
                else:
                    console.print("[red]Failed to retrieve CSRF tokens[/]")
                    return False
            return False
        return False

    def authenticate(self, email: str, password: str) -> bool:
        if not email or not password:
            console.print("[red]Error: Email and password are required[/]")
            return False

        self.email = email
        self.client_id = self._get_session_id(email)
        cookie_path, session_path = self._get_paths(email)

        # Initialize cookie jar for this email
        self.session.cookies = LoggingCookieJar(filename=cookie_path)
        policy = cookielib.DefaultCookiePolicy(
            allowed_domains=None,
            strict_domain=False,
        )
        self.session.cookies.set_policy(policy)

        # Try to load existing cookies
        if os.path.exists(cookie_path):
            try:
                self.session.cookies.load(ignore_discard=True, ignore_expires=True)
                console.print(f"Loaded cookies for {email}")
                self._log_cookies("Existing cookies for this account:")
            except Exception as e:
                console.print(f"Failed to load cookies: {e}")

        # Try to load existing session data
        if os.path.exists(session_path):
            try:
                with open(session_path) as f:
                    self.session_data = json.load(f)
                    console.print(f"Loaded existing session for {email}")
            except Exception:
                self.session_data = {"client_id": self.client_id, "email": email}
        else:
            self.session_data = {"client_id": self.client_id, "email": email}

        # Try to use existing session first
        if self.validate_token():
            console.print("Using existing session")
            return True

        console.print("Session invalid or expired, authenticating from scratch...")
        # Only clear session data, keep cookies
        self.session_data = {"client_id": self.client_id, "email": email}

        # Password handler class from iCloud implementation
        class SrpPassword:
            def __init__(self, password: str):
                if not isinstance(password, str):
                    raise ValueError("Password must be a string")
                self.password = password

            def set_encrypt_info(self, salt: bytes, iterations: int, key_length: int):
                self.salt = salt
                self.iterations = iterations
                self.key_length = key_length

            def encode(self):
                password_hash = hashlib.sha256(self.password.encode("utf-8")).digest()
                return hashlib.pbkdf2_hmac(
                    "sha256",
                    password_hash,
                    self.salt,
                    self.iterations,
                    self.key_length,
                )

        # Setup SRP
        srp_password = SrpPassword(password)
        srp.rfc5054_enable()
        srp.no_username_in_x()
        usr = srp.User(email, srp_password, hash_alg=srp.SHA256, ng_type=srp.NG_2048)

        # Start authentication
        uname, A = usr.start_authentication()

        # If session_id and scnt exist, include them in headers
        headers = {
            "Accept": "application/json, text/javascript",
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
            "X-Apple-Widget-Key": self.widget_key,
        }

        if self.session_data.get("session_id"):
            headers.update(
                {
                    "X-Apple-ID-Session-Id": self.session_data["session_id"],
                    "scnt": self.session_data["scnt"],
                }
            )

        # Send init request
        init_data = {
            "a": base64.b64encode(A).decode(),
            "accountName": uname,
            "protocols": ["s2k", "s2k_fo"],
        }

        console.print("Initializing authentication...")
        init_response = self.session.post(
            f"{self.auth_endpoint}/signin/init", headers=headers, json=init_data
        )

        # Process challenge
        body = init_response.json()
        salt = base64.b64decode(body["salt"])
        b = base64.b64decode(body["b"])
        c = body["c"]
        iterations = body["iteration"]
        key_length = 32

        # Set encryption info and process challenge
        srp_password.set_encrypt_info(salt, iterations, key_length)
        m1 = usr.process_challenge(salt, b)
        m2 = usr.H_AMK

        # Complete authentication
        complete_data = {
            "accountName": uname,
            "c": c,
            "m1": base64.b64encode(m1).decode(),
            "m2": base64.b64encode(m2).decode(),
            "rememberMe": True,
        }

        # Need to match Fastlane's URL structure exactly
        console.print("Completing authentication...")
        complete_response = self.session.post(
            f"{self.auth_endpoint}/signin/complete",
            params={"isRememberMeEnabled": "true"},
            json=complete_data,
            headers=headers,
        )

        console.print(f"[blue]Complete response:[/] {complete_response.status_code}")
        # Don't print the complete response text as it may contain sensitive data
        if complete_response.status_code not in (200, 204):
            console.print("[yellow]Response indicates additional action needed[/]")

        # Handle 409 response (2FA required)
        if complete_response.status_code == 409:
            console.print("[yellow]2FA Required![/]")

            if os.getenv("NON_INTERACTIVE"):
                console.print(
                    "[red]2FA required but NON_INTERACTIVE mode is enabled[/]"
                )
                return False

            session_id = complete_response.headers.get("X-Apple-ID-Session-Id")
            scnt = complete_response.headers.get("scnt")

            code = input("Enter the verification code: ")

            verify_headers = {
                "Accept": "application/json, text/javascript",
                "Content-Type": "application/json",
                "X-Requested-With": "XMLHttpRequest",
                "X-Apple-ID-Session-Id": session_id,
                "scnt": scnt,
                "X-Apple-Widget-Key": self.widget_key,
            }

            verify_data = {"securityCode": {"code": code.strip()}}

            try:
                # First verify the security code
                verify_response = self.session.post(
                    f"{self.auth_endpoint}/verify/trusteddevice/securitycode",
                    json=verify_data,
                    headers=verify_headers,
                )

                console.print(
                    f"[blue]Verify response:[/] {verify_response.status_code}"
                )

                if verify_response.status_code == 204:
                    console.print("[green]2FA verification successful[/]")
                    # Then request trust for the session
                    trust_response = self.session.get(
                        f"{self.auth_endpoint}/2sv/trust",
                        headers=verify_headers,
                    )

                    console.print(f"Trust response: {trust_response.status_code}")

                    if trust_response.status_code == 204:
                        # Store ALL relevant session data
                        self.session_data.update(
                            {
                                "session_id": session_id,
                                "scnt": scnt,
                                "client_id": self.client_id,  # Important to save this
                                "email": email,  # Save email for session verification
                            }
                        )
                        self.save_session()
                        console.print("Session data saved after 2FA")
                        return True

            except Exception as e:
                console.print(f"Verification failed: {e}")

            return False

        # After successful authentication, get CSRF tokens
        response = self.session.get("https://developer.apple.com/account")
        if response.status_code == 200:
            # Extract CSRF tokens from cookies using the correct method
            self.csrf = self._get_cookie_value("csrf")
            self.csrf_ts = self._get_cookie_value("csrf_ts")

            if not self.csrf or not self.csrf_ts:
                # Try to extract from page content if not in cookies
                match = re.search(r'csrf["\']\s*:\s*["\']([^"\']+)["\']', response.text)
                if match:
                    self.csrf = match.group(1)
                match = re.search(
                    r'csrf_ts["\']\s*:\s*["\']([^"\']+)["\']', response.text
                )
                if match:
                    self.csrf_ts = match.group(1)

            # Save session data after successful authentication
            if complete_response.status_code in (200, 302):
                session_id = complete_response.headers.get("X-Apple-ID-Session-Id")
                scnt = complete_response.headers.get("scnt")
                if session_id and scnt:
                    self.session_data.update(
                        {
                            "session_id": session_id,
                            "scnt": scnt,
                            "client_id": self.client_id,
                            "email": email,
                        }
                    )
                    self.save_session()
                    console.print("Session data saved after authentication")

        return complete_response.status_code in (200, 302, 409)

    def get_bundle_ids(self) -> bool:
        """Test accessing the developer portal API."""
        headers = {
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/vnd.api+json",
            "X-Requested-With": "XMLHttpRequest",
            "X-HTTP-Method-Override": "GET",
            "Origin": "https://developer.apple.com",
            "Referer": "https://developer.apple.com/account/resources/identifiers/list",
            "X-Apple-ID-Session-Id": self.session_data.get("session_id"),
            "scnt": self.session_data.get("scnt"),
        }

        try:
            response = self.session.get(
                "https://developer.apple.com/services-account/v1/certificates",
                headers=headers,
            )
            console.print(f"Certificates response: {response.status_code}")
            return (
                response.status_code == 403
            )  # 403 means we're authenticated but need team
        except Exception as e:
            console.print(f"Certificates request failed: {e}")
            return False

    def _get_auth_headers(self, overrides=None) -> dict:
        """Get auth headers exactly like their implementation"""
        headers = {
            "Accept": "application/json, text/javascript",
            "Content-Type": "application/json",
            "X-Apple-OAuth-Client-Id": "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d",
            "X-Apple-OAuth-Client-Type": "firstPartyAuth",
            "X-Apple-OAuth-Redirect-URI": "https://www.icloud.com",
            "X-Apple-OAuth-Require-Grant-Code": "true",
            "X-Apple-OAuth-Response-Mode": "web_message",
            "X-Apple-OAuth-Response-Type": "code",
            "X-Apple-OAuth-State": self.client_id,
            "X-Apple-Widget-Key": self.widget_key,
        }
        if overrides:
            headers.update(overrides)
        return headers

    def _log_cookies(self, message="Current cookies:"):
        """Helper method to log all cookies in the session"""
        console.print(f"\n[cyan]{message}[/]")
        for cookie in self.session.cookies:
            expires = (
                "never"
                if cookie.expires is None
                else f"expires {datetime.fromtimestamp(cookie.expires, tz=timezone.utc).strftime('%Y-%m-%d %H:%M:%S')} UTC"
            )
            console.print(
                f"[dim cyan]- {cookie.name}={cookie.value[:20]}... "
                f"(Domain: {cookie.domain}, {expires})[/]"
            )
        console.print("")


def main():
    email, password = get_apple_credentials()
    custom_session = get_session_dir()

    if not email:
        console.print("[red]Error: APPLE_ID environment variable is not set[/]")
        return False

    tester = AppleDeveloperAuth()

    # Try loading existing session first
    if custom_session:
        console.print(f"Attempting to load session from: {custom_session}")
        tester.email = email
        try:
            tester.load_session()
            if tester.validate_token():
                console.print("[green]Successfully loaded existing session![/]")
                return True
        except Exception as e:
            console.print(f"[yellow]Failed to load session: {e}[/]")

    # Fall back to password auth if no valid session
    if not password:
        console.print("[red]Error: No valid session and APPLE_PASSWORD not set[/]")
        return False

    console.print(f"Using Apple ID: {email}")
    console.print("Starting Apple Developer Authentication")

    try:
        if tester.authenticate(email, password):
            console.print("[green]Authentication successful![/]")
            console.print("Verifying API access...")
            if tester.get_bundle_ids():
                console.print("[green]Successfully verified API access![/]")
                return True
            else:
                console.print("[red]Failed to verify API access[/]")
                return False
        else:
            console.print("[red]Authentication failed![/]")
            return False
    except Exception as e:
        console.print(f"[red]Authentication error: {str(e)}[/]")
        return False


if __name__ == "__main__":
    main()
