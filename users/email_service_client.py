import requests
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

# Email service configuration
import os
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
        logger.info("Sending OTP via email service url=%s email=%s", url, email)
        
        # Send request with timeout
        response = requests.post(url, json=data, timeout=60)
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
            
    except requests.exceptions.Timeout:
        logger.error(f"Email service timeout for {email}")
        return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Email service request error for {email}: {str(e)}")
        return False
    except Exception as e:
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
        logger.info("Sending welcome via email service url=%s email=%s username=%s", url, email, username)
        
        # Send request with timeout
        response = requests.post(url, json=data, timeout=60)
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
            
    except requests.exceptions.Timeout:
        logger.error(f"Email service timeout for {email}")
        return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Email service request error for {email}: {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Email service error for {email}: {str(e)}")
        return False
