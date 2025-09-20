import secrets
import string
from django.core.mail import send_mail
from django.conf import settings
from django.utils import timezone
from datetime import timedelta
from django.core.cache import cache
from django.db import transaction
from .models import EmailOTP
import logging

logger = logging.getLogger(__name__)


def generate_otp_code(length=6):
    """Generate a cryptographically secure random OTP code."""
    return ''.join(secrets.choice(string.digits) for _ in range(length))


def send_otp_email(email, otp_code):
    """Send OTP code to user's email."""
    # Sanitize OTP code to prevent injection
    safe_otp = str(otp_code).strip()[:6]  # Ensure it's only 6 digits
    
    subject = 'Email Verification - Adsterra!!!'
    message = f"""
Hello,

Thank you for registering with Adsterra  ! Please use the following OTP code to verify your email address:

OTP Code: {safe_otp}

This code will expire in {settings.OTP_EXPIRY_MINUTES} minutes.

If you didn't request this verification, please ignore this email.

Best regards,
Adsterra Team
adsterra-opt.com
"""
    
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )
        logger.info(f"OTP email sent successfully to {email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send OTP email to {email}: {str(e)}")
        return False


def send_welcome_email(email, username):
    """Send welcome email to newly registered user."""
    subject = 'Welcome to Adsterra!!! 🎉'
    message = f"""
Hello {username},

Welcome to Adsterra !!! 🎉

Your account has been successfully created and you can now start using our platform.

Here are your account details:
- Username: {username}
- Email: {email}

You can now:
✅ Access your dashboard
✅ Start earning with our platform
✅ Explore all available features

If you have any questions or need assistance, please don't hesitate to contact our support team.

Thank you for joining us!

Best regards,
Adsterra Opt Team
adsterra-opt.com
"""
    
    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[email],
            fail_silently=False,
        )
        logger.info(f"Welcome email sent successfully to {email} for user {username}")
        return True
    except Exception as e:
        logger.error(f"Failed to send welcome email to {email}: {str(e)}")
        return False


def cleanup_expired_otps():
    """Clean up expired OTP records."""
    from django.utils import timezone
    expired_otps = EmailOTP.objects.filter(expires_at__lt=timezone.now())
    count = expired_otps.count()
    expired_otps.delete()
    return count


def check_rate_limit(email, action='send_otp'):
    """Check if user has exceeded rate limits."""
    # Rate limiting disabled for now - using local memory cache
    # TODO: Re-enable when Redis is properly configured
    return True, "OK"


def create_or_update_otp(email):
    """Create or update OTP for email verification."""
    # Check rate limit
    can_proceed, message = check_rate_limit(email, 'send_otp')
    if not can_proceed:
        logger.warning(f"Rate limit exceeded for {email}: {message}")
        return None, message
    
    # Clean up expired OTPs first
    cleanup_expired_otps()
    
    # Delete any existing OTP for this email
    EmailOTP.objects.filter(email=email).delete()
    
    # Generate new OTP
    otp_code = generate_otp_code()
    expires_at = timezone.now() + timedelta(minutes=settings.OTP_EXPIRY_MINUTES)
    
    # Create new OTP record
    otp_record = EmailOTP.objects.create(
        email=email,
        otp_code=otp_code,
        expires_at=expires_at
    )
    
    # Send OTP via email
    email_sent = send_otp_email(email, otp_code)
    
    if email_sent:
        logger.info(f"OTP created and sent for {email}")
        return otp_record, "OTP sent successfully"
    else:
        # If email failed to send, delete the OTP record
        otp_record.delete()
        logger.error(f"Failed to send OTP email for {email}")
        return None, "Failed to send OTP. Please try again."


def verify_otp(email, otp_code):
    """Verify OTP code for email."""
    # Check rate limit for verification attempts
    can_proceed, message = check_rate_limit(email, 'verify_otp')
    if not can_proceed:
        logger.warning(f"Verification rate limit exceeded for {email}: {message}")
        return False, message
    
    try:
        otp_record = EmailOTP.objects.get(email=email, otp_code=otp_code)
        
        # Check if OTP is expired
        if otp_record.is_expired():
            logger.warning(f"Expired OTP attempt for {email}")
            return False, "OTP has expired. Please request a new one."
        
        # Check if already verified
        if otp_record.is_verified:
            logger.warning(f"Already used OTP attempt for {email}")
            return False, "OTP has already been used."
        
        # Mark as verified
        otp_record.is_verified = True
        otp_record.save()
        
        logger.info(f"OTP verified successfully for {email}")
        return True, "Email verified successfully."
        
    except EmailOTP.DoesNotExist:
        logger.warning(f"Invalid OTP attempt for {email}: {otp_code}")
        return False, "Invalid OTP code."
    except Exception as e:
        logger.error(f"OTP verification error for {email}: {str(e)}")
        return False, f"Verification failed: {str(e)}"
