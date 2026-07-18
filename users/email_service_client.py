import json
import logging
import os
import subprocess
from django.conf import settings

logger = logging.getLogger(__name__)

# Email service configuration
EMAIL_SERVICE_URL = os.getenv(
    'EMAIL_SERVICE_URL',
    getattr(settings, 'EMAIL_SERVICE_URL', 'https://email.adsterra-opt.com')
).rstrip('/')

def send_otp_via_service(email, otp_code):
    """Send OTP email via external email service"""
    try:
        url = f"{EMAIL_SERVICE_URL}/send-otp"
        data = {
            "to_email": email,
            "otp_code": otp_code
        }
        print(f"EMAIL_SERVICE_CALL: POST {url} email={email}")
        logger.info("Sending OTP via email service url=%s email=%s", url, email)
        
        response = _post_json_via_curl(url, data, timeout=60)
        print(f"EMAIL_SERVICE_RESPONSE: POST {url} status={response.status_code} body={response.text[:500]}")
        logger.info(
            "Email service response url=%s status=%s body=%s",
            url,
            response.status_code,
            response.text[:500],
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                logger.info(f"OTP email sent successfully via service to {email}")
                return True
            else:
                logger.error(f"Email service returned error: {result.get('message')}")
                return False
        else:
            logger.error(f"Email service HTTP error: {response.status_code}")
            return False
            
    except TimeoutError:
        print(f"EMAIL_SERVICE_ERROR: timeout url={url} email={email}")
        logger.error(f"Email service timeout for {email}")
        return False
    except RuntimeError as e:
        print(f"EMAIL_SERVICE_ERROR: request_exception url={url} email={email} error={e}")
        logger.error(f"Email service request error for {email}: {str(e)}")
        return False
    except Exception as e:
        print(f"EMAIL_SERVICE_ERROR: unexpected url={url} email={email} error={e}")
        logger.error(f"Email service error for {email}: {str(e)}")
        return False

def send_welcome_via_service(email, username):
    """Send welcome email via external email service"""
    try:
        url = f"{EMAIL_SERVICE_URL}/send-welcome"
        data = {
            "to_email": email,
            "username": username
        }
        print(f"EMAIL_SERVICE_CALL: POST {url} email={email} username={username}")
        logger.info("Sending welcome via email service url=%s email=%s username=%s", url, email, username)
        
        response = _post_json_via_curl(url, data, timeout=60)
        print(f"EMAIL_SERVICE_RESPONSE: POST {url} status={response.status_code} body={response.text[:500]}")
        logger.info(
            "Email service response url=%s status=%s body=%s",
            url,
            response.status_code,
            response.text[:500],
        )
        
        if response.status_code == 200:
            result = response.json()
            if result.get('success'):
                logger.info(f"Welcome email sent successfully via service to {email}")
                return True
            else:
                logger.error(f"Email service returned error: {result.get('message')}")
                return False
        else:
            logger.error(f"Email service HTTP error: {response.status_code}")
            return False
            
    except TimeoutError:
        print(f"EMAIL_SERVICE_ERROR: timeout url={url} email={email}")
        logger.error(f"Email service timeout for {email}")
        return False
    except RuntimeError as e:
        print(f"EMAIL_SERVICE_ERROR: request_exception url={url} email={email} error={e}")
        logger.error(f"Email service request error for {email}: {str(e)}")
        return False
    except Exception as e:
        print(f"EMAIL_SERVICE_ERROR: unexpected url={url} email={email} error={e}")
        logger.error(f"Email service error for {email}: {str(e)}")
        return False


def _post_json_via_curl(url, data, timeout=60):
    """Send JSON over curl with HTTP/2 enabled so LiteSpeed accepts the request."""
    payload = json.dumps(data)
    command = [
        "curl",
        "--silent",
        "--show-error",
        "--http2",
        "--max-time",
        str(timeout),
        "-H",
        "Content-Type: application/json",
        "--data-binary",
        "@-",
        "-w",
        "\\n%{http_code}",
        url,
    ]

    try:
        result = subprocess.run(
            command,
            input=payload,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as e:
        raise RuntimeError("curl command is not available") from e

    if result.returncode != 0:
        stderr = (result.stderr or "").strip()
        raise RuntimeError(stderr or f"curl exited with status {result.returncode}")

    stdout = result.stdout or ""
    if "\n" not in stdout:
        raise RuntimeError(f"Invalid curl response: {stdout[:200]}")

    body, status_text = stdout.rsplit("\n", 1)
    try:
        status_code = int(status_text.strip())
    except ValueError as e:
        raise RuntimeError(f"Invalid HTTP status from curl: {status_text!r}") from e

    class CurlResponse:
        def __init__(self, status_code, text):
            self.status_code = status_code
            self.text = text

        def json(self):
            return json.loads(self.text)

    return CurlResponse(status_code, body)
