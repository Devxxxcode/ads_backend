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
    
    subject = 'Email Verification Code - Adsterra Opt'
    message = f"""Dear User,

Thank you for registering with Adsterra Opt. To complete your account verification, please use the following verification code:

Verification Code: {safe_otp}

This code will expire in {settings.OTP_EXPIRY_MINUTES} minutes for security purposes.

If you did not request this verification code, please ignore this email and do not share this code with anyone.

For security reasons, never share your verification code with others.

Best regards,
Adsterra Opt Support Team
Website: adsterra-opt.com
"""
    
    try:
        from django.core.mail import EmailMessage
        import time
        
        # Retry logic for email sending - minimal retries for slow server
        max_retries = 1  # Only 1 retry to prevent long timeouts
        retry_delay = 2  # seconds
        
        for attempt in range(max_retries):
            try:
                email_msg = EmailMessage(
                    subject=subject,
                    body=message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    to=[email],
                    headers={
                        'X-Mailer': 'Adsterra Opt System',
                        'X-Priority': '3',
                        'X-MSMail-Priority': 'Normal',
                        'Importance': 'Normal',
                    }
                )
                email_msg.send(fail_silently=False)
                logger.info(f"OTP email sent successfully to {email} (attempt {attempt + 1})")
                return True
                
            except Exception as e:
                logger.warning(f"OTP email attempt {attempt + 1} failed for {email}: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    raise e
                    
    except Exception as e:
        logger.error(f"Failed to send OTP email to {email} after {max_retries} attempts: {str(e)}")
        return False


def send_welcome_email(email, username):
    """Send welcome email to newly registered user."""
    subject = 'Welcome to Adsterra Opt - Account Created Successfully'
    message = f"""Dear {username},

Welcome to Adsterra Opt! Your account has been successfully created and verified.

Account Information:
- Username: {username}
- Email Address: {email}

Your account is now active and you can:

1. Access your personal dashboard
2. Start using our platform features
3. Explore available opportunities
4. Manage your account settings

If you have any questions or need assistance, please contact our support team.

Thank you for choosing Adsterra Opt!

Best regards,
Adsterra Opt Support Team
Website: adsterra-opt.com
"""
    
    try:
        from django.core.mail import EmailMessage
        import time
        import socket
        
        # Retry logic for email sending with shorter timeouts for welcome emails
        max_retries = 2  # Fewer retries for welcome emails
        retry_delay = 1  # Shorter delay
        
        for attempt in range(max_retries):
            try:
                email_msg = EmailMessage(
                    subject=subject,
                    body=message,
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    to=[email],
                    headers={
                        'X-Mailer': 'Adsterra Opt System',
                        'X-Priority': '3',
                        'X-MSMail-Priority': 'Normal',
                        'Importance': 'Normal',
                    }
                )
                
                # Set shorter timeout for welcome emails
                email_msg.timeout = 15  # 15 seconds timeout
                email_msg.send(fail_silently=False)
                logger.info(f"Welcome email sent successfully to {email} for user {username} (attempt {attempt + 1})")
                return True
                
            except (socket.timeout, Exception) as e:
                logger.warning(f"Welcome email attempt {attempt + 1} failed for {email}: {str(e)}")
                if attempt < max_retries - 1:
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                else:
                    raise e
                    
    except Exception as e:
        logger.error(f"Failed to send welcome email to {email} after {max_retries} attempts: {str(e)}")
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
    logger.info(f"Creating/updating OTP for {email}")
    
    # Check rate limit
    can_proceed, message = check_rate_limit(email, 'send_otp')
    if not can_proceed:
        logger.warning(f"Rate limit exceeded for {email}: {message}")
        return None, message
    
    # Clean up expired OTPs first
    cleanup_expired_otps()
    
    # Delete any existing OTP for this email
    existing_otps = EmailOTP.objects.filter(email=email)
    if existing_otps.exists():
        logger.info(f"Deleting {existing_otps.count()} existing OTP(s) for {email}")
        existing_otps.delete()
    
    # Generate new OTP
    otp_code = generate_otp_code()
    expires_at = timezone.now() + timedelta(minutes=settings.OTP_EXPIRY_MINUTES)
    
    # Create new OTP record
    try:
        otp_record = EmailOTP.objects.create(
            email=email,
            otp_code=otp_code,
            expires_at=expires_at
        )
        logger.info(f"OTP record created for {email}: {otp_code}")
    except Exception as e:
        logger.error(f"Failed to create OTP record for {email}: {str(e)}")
        return None, "Failed to create OTP record. Please try again."
    
    # Send OTP via email in background (async)
    logger.info(f"OTP created for {email}, sending email in background")
    
    # Start email sending in background thread with timeout protection
    import threading
    import signal
    
    def send_email_async():
        try:
            # Use threading timeout instead of signal (works in background threads)
            import threading
            import time
            
            result = [None]
            exception = [None]
            
            def email_worker():
                try:
                    result[0] = send_otp_email(email, otp_code)
                except Exception as e:
                    exception[0] = e
            
            # Start email sending in a separate thread with timeout
            email_worker_thread = threading.Thread(target=email_worker)
            email_worker_thread.daemon = True
            email_worker_thread.start()
            
            # Wait for email sending with 30-second timeout
            email_worker_thread.join(timeout=30)
            
            if email_worker_thread.is_alive():
                logger.warning(f"Background email sending timed out for {email} - email server too slow")
                return
            
            if exception[0]:
                raise exception[0]
            
            if result[0]:
                logger.info(f"Background email sent successfully to {email}")
            else:
                logger.warning(f"Background email sending failed for {email}")
                
        except Exception as e:
            logger.error(f"Background email sending error for {email}: {str(e)}")
    
    # Start the email sending in a separate thread
    email_thread = threading.Thread(target=send_email_async)
    email_thread.daemon = True  # Dies when main thread dies
    email_thread.start()
    
    # Return immediately - don't wait for email
    logger.info(f"OTP created successfully for {email}, email sending initiated in background")
    return otp_record, "OTP sent successfully"


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
