from rest_framework.viewsets import ViewSet
from rest_framework_simplejwt.views import TokenRefreshView, TokenVerifyView
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework import status
from .serializers import (
    UserSignupSerializer,
    UserLoginSerializer,
    UserProfileSerializer,
    ChangePasswordSerializer,
    ChangeTransactionalPasswordSerializer,
    InvitationCodeSerializer,
    AdminAuthSerializer,
    SendOTPSerializer,
    VerifyOTPSerializer,
    UserSignupWithOTPSerializer
)
from administration.serializers import SettingsSerializer
from rest_framework.exceptions import NotFound
from shared.helpers import get_settings
from rest_framework.decorators import api_view
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from shared.utils import standard_response as Response
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from rest_framework_simplejwt.tokens import RefreshToken
from core.permissions import IsSiteAdmin
from .models import InvitationCode
from rest_framework_simplejwt.exceptions import InvalidToken
from shared.helpers import create_user_notification
from django.contrib.auth import get_user_model
from django.db import transaction
import logging

User = get_user_model()
logger = logging.getLogger(__name__)


class CustomTokenRefreshView(TokenRefreshView):
    """
    Custom refresh token view to bypass unnecessary access token checks.
    """

    authentication_classes = [] 
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        try:
            serializer.is_valid(raise_exception=True)
        except InvalidToken as e:
            return Response(
                success=False,
                message="Invalid or expired refresh token.",
                errors=e.detail,
                data=None,
                status_code=status.HTTP_401_UNAUTHORIZED
            )
        except Exception as e:
            return Response(
                success=False,
                message="Invalid or expired refresh token.",
                errors=None,
                data=None,
                status_code=status.HTTP_401_UNAUTHORIZED
            )

        return Response(
            success=True,
            message="Token refreshed successfully.",
            data=serializer.validated_data,
            errors=None,
            status_code=status.HTTP_200_OK
        )
    

class UserAuthViewSet(ViewSet):
    """
    ViewSet for managing user authentication and profiles.
    """

    @swagger_auto_schema(
        request_body=UserSignupSerializer,
        responses={201: UserSignupSerializer},
        operation_summary="User Signup (Legacy)",
        operation_description="Create a new user without OTP verification. Use signup_with_otp for new registrations."
    )
    @action(detail=False, methods=['post'])
    def signup(self, request):
        serializer = UserSignupSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            success=True,
            message="User created successfully.",
            status_code=status.HTTP_201_CREATED,
            data=serializer.data
        )

    @swagger_auto_schema(
        request_body=SendOTPSerializer,
        responses={200: "OTP sent successfully."},
        operation_summary="Send OTP for Email Verification",
        operation_description="Send OTP code to user's email for verification during signup."
    )
    @action(detail=False, methods=['post'], permission_classes=[AllowAny])
    def send_otp(self, request):
        serializer = SendOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        result = serializer.save()
        return Response(
            success=True,
            message=result["message"],
            status_code=status.HTTP_200_OK
        )

    @swagger_auto_schema(
        request_body=VerifyOTPSerializer,
        responses={200: "OTP verified successfully."},
        operation_summary="Verify OTP Code",
        operation_description="Verify the OTP code sent to user's email."
    )
    @action(detail=False, methods=['post'], permission_classes=[AllowAny])
    def verify_otp(self, request):
        serializer = VerifyOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        return Response(
            success=True,
            message="Email verified successfully. You can now complete your registration.",
            status_code=status.HTTP_200_OK
        )

    @swagger_auto_schema(
        request_body=UserSignupWithOTPSerializer,
        responses={201: UserSignupWithOTPSerializer},
        operation_summary="User Signup with OTP Verification",
        operation_description="Create a new user with email OTP verification."
    )
    @action(detail=False, methods=['post'], permission_classes=[AllowAny])
    def signup_with_otp(self, request):
        serializer = UserSignupWithOTPSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(
            success=True,
            message="User created successfully. Email verified.",
            status_code=status.HTTP_201_CREATED,
            data=serializer.data
        )

    @swagger_auto_schema(
        request_body=UserLoginSerializer,
        responses={
            200: openapi.Response(
                description="Login successful.",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "access_token": openapi.Schema(type=openapi.TYPE_STRING),
                        "refresh_token": openapi.Schema(type=openapi.TYPE_STRING),
                        "user": openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                "username": openapi.Schema(type=openapi.TYPE_STRING),
                                "email": openapi.Schema(type=openapi.TYPE_STRING),
                                "phone_number": openapi.Schema(type=openapi.TYPE_STRING),
                            }
                        ),
                    },
                )
            )
        },
        operation_summary="User Login",
        operation_description="Authenticate a user and return JWT tokens."
    )
    @action(detail=False, methods=['post'], permission_classes=[AllowAny])
    def login(self, request):
        serializer = UserLoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        return Response(
            success=True,
            message="Login successful.",
            data={
                "access_token": access_token,
                "refresh_token": refresh_token,
                "user": {
                    "username": user.username,
                    "email": user.email,
                    "phone_number": getattr(user, 'phone_number', None),
                }
            },
            status_code=status.HTTP_200_OK
        )

    @swagger_auto_schema(
        responses={200: "Logout successful."},
        operation_summary="User Logout",
        operation_description="Logs out the authenticated user."
    )
    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def logout(self, request):
        request.user.auth_token.delete()
        return Response(
            success=True,
            message="Logout successful.",
            status_code=status.HTTP_200_OK
        )

    @swagger_auto_schema(
        responses={200: UserProfileSerializer},
        operation_summary="Get Profile",
        operation_description="Retrieve the current authenticated user's profile."
    )
    @action(detail=False, methods=['get'], permission_classes=[IsAuthenticated])
    def me(self, request):
        serializer = UserProfileSerializer(request.user)
        return Response(
            success=True,
            message="User profile retrieved successfully.",
            data=serializer.data,
            status_code=status.HTTP_200_OK
        )


    @swagger_auto_schema(
        request_body=UserProfileSerializer,
        responses={200: UserProfileSerializer},
        operation_summary="Update User Profile",
        operation_description="Update the authenticated user's profile, including uploading a profile picture."
    )
    @action(detail=False, methods=['patch'], permission_classes=[IsAuthenticated], parser_classes=[MultiPartParser])
    def update_profile(self, request):
        """
        Update the current user's profile.
        """
        serializer = UserProfileSerializer(request.user, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        create_user_notification(request.user,"Profile Update","Your Profile was updated successfully")
        return Response(
            success=True,
            message="Profile updated successfully.",
            data=serializer.data,
            status_code=status.HTTP_200_OK
        )

    @swagger_auto_schema(
        request_body=ChangePasswordSerializer,
        responses={200: "Password changed successfully."},
        operation_summary="Change Password",
        operation_description="Change the authenticated user's password."
    )
    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def user_change_password(self, request):
        serializer = ChangePasswordSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        create_user_notification(request.user,"Password Changed", "Your account password has successfully been updated")
        return Response(
            success=True,
            message="Password changed successfully.",
            status_code=status.HTTP_200_OK
        )
    
    @swagger_auto_schema(
        operation_description="Change the transactional password for the authenticated user.",
        operation_summary="Change transactional Password",
        request_body=ChangeTransactionalPasswordSerializer,  # Attach the request body schema
        responses={
            200: openapi.Response(
                description="Transactional password changed successfully.",
                examples={
                    "application/json": {
                        "success": True,
                        "message": "Transaction Password changed successfully.",
                    }
                },
            ),
            400: openapi.Response(
                description="Validation error.",
                examples={
                    "application/json": {
                        "success": False,
                        "message": "Validation failed.",
                        "data": {
                            "current_password": ["This field is required."],
                            "new_password": ["This field is required."],
                        },
                    }
                },
            ),
        },
    )
    @action(detail=False, methods=['post'], permission_classes=[IsAuthenticated])
    def user_change_transactional_password(self, request):
        serializer = ChangeTransactionalPasswordSerializer(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        create_user_notification(request.user,"Transactional Password Changed", "Your transaction password has successfully been updated")
        return Response(
            success=True,
            message="Transaction Password changed successfully.",
            status_code=status.HTTP_200_OK,
        )
    

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "refresh": openapi.Schema(type=openapi.TYPE_STRING, description="The refresh token to be used."),
            },
            required=["refresh"]
        ),
        responses={
            200: openapi.Response(
                description="New access token.",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "access": openapi.Schema(type=openapi.TYPE_STRING, description="New access token."),
                    },
                )
            )
        },
        operation_summary="Refresh Token",
        operation_description="Use the refresh token to get a new access token."
    )
    @action(detail=False, methods=['post'], url_path='refresh-token', permission_classes=[AllowAny])
    def refresh_token(self, request):
        """
        Handle token refreshing using the SimpleJWT TokenRefreshView logic.
        """
        return CustomTokenRefreshView.as_view()(request._request)

    @swagger_auto_schema(
        request_body=openapi.Schema(
            type=openapi.TYPE_OBJECT,
            properties={
                "token": openapi.Schema(type=openapi.TYPE_STRING, description="The token to verify."),
            },
            required=["token"]
        ),
        responses={
            200: openapi.Response(
                description="Token is valid.",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "detail": openapi.Schema(type=openapi.TYPE_STRING, description="Token is valid."),
                    },
                )
            )
        },
        operation_summary="Verify Token",
        operation_description="Verify the validity of an access or refresh token."
    )
    @action(detail=False, methods=['post'], url_path='verify-token', permission_classes=[AllowAny])
    def verify_token(self, request):
        """
        Handle token verification using the SimpleJWT TokenVerifyView logic.
        """
        return TokenVerifyView.as_view()(request._request)

    @action(detail=False, methods=['get'], url_path='settings', permission_classes=[AllowAny])
    def site_settings(self,request):
        """
        Return all the site settings create by the admin
        """
        instance = get_settings()
        if not instance:
            raise NotFound(detail="Settings not found.")
        serializer = SettingsSerializer(instance=instance)
        return Response(
            success=True,
            message="Settings Fetched successfully.",
            data=serializer.data,
            status_code=status.HTTP_200_OK
        )
    

class InvitationCodeViewSet(ViewSet):
    """
    ViewSet for managing Invitation Codes.
    """
    permission_classes = [IsSiteAdmin]

    @action(detail=False, methods=['post'], url_path='generate-code')
    def generate_invitation_code(self, request):
        """
        Generate a new invitation code.
        """
        # Create a new InvitationCode instance
        invitation_code = InvitationCode.objects.create()

        # Serialize the new invitation code
        serializer = InvitationCodeSerializer(invitation_code)
        
        return Response(
            success=True,
            message="Invitation code generated successfully.",
            data=serializer.data,
            status_code=status.HTTP_201_CREATED
        )

class AdminAuthViewSet(ViewSet):
    """
    ViewSet for Admin-related operations, including login.
    """

    @swagger_auto_schema(
        request_body=AdminAuthSerializer.Login,
        responses={
            200: openapi.Response(
                description="Login successful.",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "access": openapi.Schema(type=openapi.TYPE_STRING),
                        "refresh": openapi.Schema(type=openapi.TYPE_STRING),
                        "user": openapi.Schema(
                            type=openapi.TYPE_OBJECT,
                            properties={
                                "username": openapi.Schema(type=openapi.TYPE_STRING),
                                "email": openapi.Schema(type=openapi.TYPE_STRING),
                                "phone_number": openapi.Schema(type=openapi.TYPE_STRING),
                                "is_staff": openapi.Schema(type=openapi.TYPE_BOOLEAN),
                            }
                        ),
                    },
                )
            ),
            400: openapi.Response(description="Invalid credentials or not an admin."),
        },
        operation_summary="Admin Login",
        operation_description="Authenticate an admin user and return JWT tokens.",
    )
    @action(detail=False, methods=['post'], permission_classes=[AllowAny])
    def login(self, request):
        serializer = AdminAuthSerializer.Login(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']

        # Generate JWT tokens
        refresh = RefreshToken.for_user(user)
        access_token = str(refresh.access_token)
        refresh_token = str(refresh)

        return Response(
            success=True,
            message="Dashboard data retrieved successfully.",
            data={
                "access": access_token,
                "refresh": refresh_token,
                "user": {
                    "username": user.username,
                    "email": user.email,
                    "phone_number": getattr(user, 'phone_number', None),
                    "is_staff": user.is_staff,
                },
            },
            status_code=status.HTTP_200_OK,
        )
    

    @swagger_auto_schema(
        responses={200: AdminAuthSerializer.List()},
        operation_summary="Get Admin Profile",
        operation_description="Retrieve the current authenticated admin user's profile.",
    )
    @action(detail=False, methods=['get'], permission_classes=[IsSiteAdmin])
    def me(self, request):
        """
        Action to retrieve the authenticated admin's profile.
        Restricted to users with IsSiteAdmin permission.
        """
        user = request.user

        # Serialize the user data with AdminAuthSerializer.List
        serializer = AdminAuthSerializer.List(user)

        return Response(
            success=True,
            message="Admin profile retrieved successfully.",
            data=serializer.data,
            status_code=status.HTTP_200_OK,
        )
