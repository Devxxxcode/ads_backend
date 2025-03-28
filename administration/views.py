from rest_framework.viewsets import GenericViewSet,ViewSet,ModelViewSet
from rest_framework.exceptions import NotFound
from drf_yasg.utils import swagger_auto_schema
from django.db.models import Count, Q, F ,OrderBy, Value
from django.db.models.functions import Coalesce
from rest_framework.filters import OrderingFilter,SearchFilter
from drf_yasg import openapi
from rest_framework.parsers import MultiPartParser, FormParser
from rest_framework.decorators import action
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from .models import Settings,Event
from .serializers import SettingsSerializer,DepositSerializer,SettingsVideoSerializer,EventSerializer,WithdrawalSerializer
from shared.utils import standard_response as Response
from shared.helpers import get_settings,create_admin_log
from shared.mixins import StandardResponseMixin
from core.permissions import IsSiteAdmin,IsAdminOrReadOnly
from finances.models import Deposit,Withdrawal
from cloudinary.uploader import upload
from rest_framework.exceptions import ValidationError
from rest_framework.viewsets import ReadOnlyModelViewSet
from django.contrib.auth import get_user_model
from users.serializers import UserProfileListSerializer,AdminUserUpdateSerializer
from wallet.serializers import OnHoldPaySerializer
from wallet.models import OnHoldPay
from game.models import Game
from game.serializers import AdminNegativeUserSerializer


User = get_user_model()


class SettingsViewSet(GenericViewSet):
    """
    ViewSet for managing the global Settings instance.
    Provides GET (retrieve), PUT (update), and POST (update video) operations.
    """
    permission_classes = [IsAuthenticated, IsSiteAdmin]
    queryset = Settings.objects.all()

    def get_serializer_class(self):
        """
        Dynamically return the appropriate serializer class based on the action.
        """
        if self.action == "retrieve":
            return SettingsSerializer
        elif self.action == "update_video":
            return SettingsVideoSerializer
        return SettingsSerializer
    
    @swagger_auto_schema(
    operation_summary="Retrieve Settings",
    operation_description="Retrieve the global settings instance.",
    responses={
        200: openapi.Response("Settings retrieved successfully", SettingsSerializer),
        404: "Settings not found",
    },
)
    def list(self, request, *args, **kwargs):
        """
        Handle GET request for settings.
        """
        instance = get_settings()
        if not instance:
            raise NotFound(detail="Settings not found.")
        serializer = self.get_serializer(instance)
        return Response(
            success=True,
            message="Settings retrieved successfully.",
            data=serializer.data,
            status_code=status.HTTP_200_OK
        )

    @action(detail=False, methods=["patch"], url_path="update-settings")
    def update_settings(self, request):
        """
        Handle PATCH request to partially update settings.
        """
        instance = get_settings()
        if not instance:
            raise NotFound(detail="Settings not found.")
        serializer = self.get_serializer(instance, data=request.data, partial=True)  # Partial update enabled
        serializer.is_valid(raise_exception=True)
        serializer.save()
        create_admin_log(request,"Updated the site settings")
        return Response(
            success=True,
            message="Settings updated successfully.",
            data=serializer.data,
            status_code=status.HTTP_200_OK
        )


    @swagger_auto_schema(
    operation_summary="Update Video",
    operation_description="Upload and update the video field in the settings.",
    manual_parameters=[
        openapi.Parameter(
            name="video",
            in_=openapi.IN_FORM,
            type=openapi.TYPE_FILE,
            description="The video file to upload",
            required=True,
        )
    ],
    responses={
        200: openapi.Response(
            description="Video updated successfully.",
            examples={
                "application/json": {
                    "success": True,
                    "message": "Video updated successfully.",
                    "data": {
                        "video": "/media/videos/example.mp4"
                    }
                }
            },
        ),
        400: "No video file provided.",
        404: "Settings not found.",
    },)
    @action(detail=False, methods=["post"], url_path="update-video", parser_classes=[MultiPartParser, FormParser])
    def update_video(self, request):
        """
        Update the video field in the settings.
        """
        instance = Settings.objects.first()
        if not instance:
            raise NotFound(detail="Settings not found.")

        serializer = SettingsVideoSerializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        create_admin_log(request,"Updated the site video for the worker platform")
        return Response(
            success=True,
            message="Video updated successfully.",
            data=serializer.data,
            status_code=status.HTTP_200_OK
        )


class AdminDepositViewSet(StandardResponseMixin, ViewSet):
    """
    Admin ViewSet for listing all deposits and updating the status of a deposit instance.
    """
    permission_classes = [IsSiteAdmin]

    def get_serializer_class(self):
        """
        Map the action to the appropriate serializer class.
        """
        action_to_serializer = {
            "list": DepositSerializer.List,
            "update_status": DepositSerializer.UpdateStatus,
        }
        return action_to_serializer.get(self.action, DepositSerializer.List)

    def list(self, request):
        """
        List all deposits for admin users.
        """
        if getattr(self, 'swagger_fake_view', False):
            return Response([], status=status.HTTP_200_OK)

        deposits = Deposit.objects.all().order_by('date_time')
        serializer_class = self.get_serializer_class()
        serializer = serializer_class(deposits, many=True)
        return Response(
            success=True,
            message="All deposits retrieved successfully.",
            data=serializer.data,
            status_code=status.HTTP_200_OK,
        )

    @action(detail=True, methods=["patch"], url_path="update-status")
    def update_status(self, request, pk=None):
        """
        Update the status of a specific deposit instance.
        """
        try:
            deposit = Deposit.objects.get(pk=pk)
        except Deposit.DoesNotExist:
            return Response(
                success=False,
                message="Deposit not found.",
                data={},
                status_code=status.HTTP_404_NOT_FOUND,
            )

        serializer_class = self.get_serializer_class()
        serializer = serializer_class(deposit, data=request.data, partial=True, context={"request": request})
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            success=True,
            message="Deposit status updated successfully.",
            data=serializer.data,
            status_code=status.HTTP_200_OK,
        )

class AdminWithdrawalViewSet(StandardResponseMixin, ViewSet):
    """
    Admin ViewSet for listing all withdrawals and updating the status of a withdrawal instance.
    """
    permission_classes = [IsSiteAdmin]

    def get_serializer_class(self):
        """
        Map the action to the appropriate serializer class.
        """
        action_to_serializer = {
            "list": WithdrawalSerializer.List,
            "update_status": WithdrawalSerializer.UpdateStatus,
        }
        return action_to_serializer.get(self.action, WithdrawalSerializer.List)

    @swagger_auto_schema(
        operation_summary="List All Withdrawals",
        operation_description=(
            "Retrieve a list of all withdrawal requests, ordered by creation date. "
            "Accessible only to admin users."
        ),
        responses={
            200: openapi.Response(
                description="List of withdrawals",
                schema=WithdrawalSerializer.List(many=True)
            ),
            403: openapi.Response(description="Permission Denied"),
        },
    )
    def list(self, request):
        """
        List all withdrawals for admin users.
        """
        if getattr(self, 'swagger_fake_view', False):
            return Response([], status=status.HTTP_200_OK)

        withdrawals = Withdrawal.objects.all().order_by('-created_at')
        serializer_class = self.get_serializer_class()
        serializer = serializer_class(withdrawals, many=True)
        return Response(
            success=True,
            message="All withdrawals retrieved successfully.",
            data=serializer.data,
            status_code=status.HTTP_200_OK,
        )

    @swagger_auto_schema(
        operation_summary="Update Withdrawal Status",
        operation_description=(
            "Update the status of a specific withdrawal request. "
            "Allowed statuses are 'Processed' and 'Rejected'. "
            "This endpoint also updates the user's wallet balance and notifies them of the status change."
        ),
        request_body=WithdrawalSerializer.UpdateStatus,
        responses={
            200: openapi.Response(
                description="Withdrawal status updated successfully",
                schema=WithdrawalSerializer.UpdateStatus
            ),
            404: openapi.Response(description="Withdrawal not found"),
            400: openapi.Response(description="Validation error"),
        },
        manual_parameters=[
            openapi.Parameter(
                name="id",
                in_=openapi.IN_PATH,
                description="ID of the withdrawal request to update",
                type=openapi.TYPE_INTEGER,
                required=True,
            )
        ],
    )
    @action(detail=True, methods=["patch"], url_path="update-status")
    def update_status(self, request, pk=None):
        """
        Update the status of a specific withdrawal instance.
        """
        try:
            withdrawal = Withdrawal.objects.get(pk=pk)
        except Withdrawal.DoesNotExist:
            return Response(
                success=False,
                message="Withdrawal not found.",
                data=None,
                status_code=status.HTTP_404_NOT_FOUND,
            )

        serializer_class = self.get_serializer_class()
        serializer = serializer_class(withdrawal, data=request.data, partial=True, context={"request": request})
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(
            success=True,
            message="Withdrawal status updated successfully.",
            data=serializer.data,
            status_code=status.HTTP_200_OK,
        )



class EventViewSet(StandardResponseMixin,ModelViewSet):
    """
    ViewSet for managing events.
    Only admin users are allowed to access this viewset.
    """

    parser_classes = [FormParser, MultiPartParser]
    
    queryset = Event.objects.all()
    serializer_class = EventSerializer
    permission_classes = [IsSiteAdmin]

    def create(self, request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        create_admin_log(
            request=request,
            message="Created a new event",
        )
        return response
    
    def update(self, request, *args, **kwargs):
        response = super().update(request, *args, **kwargs)
        create_admin_log(
            request=request,
            message=f"Updated event with name: {response.data.name}.",
        )
        return response
    
    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        create_admin_log(
            request=request,
            message=f"Deleted event with name: {instance.name}.",
        )
        response = super().destroy(request, *args, **kwargs)
        return response



class AdminUserManagementViewSet(StandardResponseMixin,ReadOnlyModelViewSet):
    serializer_class = UserProfileListSerializer
    permission_classes = [IsSiteAdmin]

    def get_queryset(self):
        """
        Annotate the queryset with complex fields and return it.
        """
        return User.objects.users().annotate(
            total_games_played=Count('games', filter=Q(games__played=True)),
            total_negative_product=Count('games', filter=Q(games__played=True)& Q(games__special_product=True)),
            wallet_commission=F('wallet__commission')
        )

    filter_backends = [OrderingFilter, SearchFilter]
    search_fields = ['username', 'email', 'phone_number','first_name','last_name']
    ordering_fields = ['wallet__commission', 'total_games_played', 'total_negative_product',] 
    ordering = ['-id'] 

    def get_serializer_class(self):
        """
        Dynamically determine which serializer to use based on the action.
        """
        if self.action == 'update_login_password':
            return AdminUserUpdateSerializer.LoginPassword
        elif self.action == 'update_withdrawal_password':
            return AdminUserUpdateSerializer.WithdrawalPassword
        elif self.action == 'update_user_balance':
            return AdminUserUpdateSerializer.UserBalance
        elif self.action == 'update_user_profit':
            return AdminUserUpdateSerializer.UserProfit
        elif self.action == 'update_user_salary':
            return AdminUserUpdateSerializer.UserSalary
        elif self.action == 'toggle_reg_bonus':
            return AdminUserUpdateSerializer.ToggleRegBonus
        elif self.action == 'toggle_user_min_balance':
            return AdminUserUpdateSerializer.ToggleUserMinBalanceForSubmission
        elif self.action == 'get_user_info':
            return AdminUserUpdateSerializer.UserProfile
        elif self.action == 'toggle_user_active':
            return AdminUserUpdateSerializer.ToggleUserActive
        elif self.action == "reset_user_account":
            return AdminUserUpdateSerializer.ResetUserAccount
        elif self.action == "update_credit_score":
            return AdminUserUpdateSerializer.UpdateUserCeditScore
        return super().get_serializer_class()
    
    
    def handle_action_response(self, data, message="Action completed successfully.",override_serializer=None):
        """
        Centralized function to handle responses using UserProfile serializer.
        Returns a standardized response.
        """
        if not override_serializer:
            serializer = UserProfileListSerializer(instance=data)
        else:
            serializer = override_serializer(instance=data)
        return self.standard_response(
                success=True,
                message=message,
                data=serializer.data,
                status_code=status.HTTP_200_OK,
            )
    @action(detail=False, methods=['post'], url_path='update-login-password')
    def update_login_password(self, request):
        """
        Update the login password for a user.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return self.handle_action_response(user,"User Password Updated Successfully")

    @action(detail=False, methods=['post'], url_path='update-withdrawal-password')
    def update_withdrawal_password(self, request):
        """
        Update the withdrawal password for a user.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return self.handle_action_response(user,"User Withdrawal Password Updated Successfully")

    @action(detail=False, methods=['post'], url_path='update-balance')
    def update_user_balance(self, request):
        """
        Update the balance for a user.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return self.handle_action_response(user, "User Balance Updated Successfully")

    @action(detail=False, methods=['post'], url_path='update-profit')
    def update_user_profit(self, request):
        """
        Update the profit for a user.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return self.handle_action_response(user,"User Total Profit Updated Successfully")

    @action(detail=False, methods=['post'], url_path='update-salary')
    def update_user_salary(self, request):
        """
        Update the salary for a user.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return self.handle_action_response(user,"User Salary Updated Successfully")

    @action(detail=False, methods=['post'], url_path='toggle-reg-bonus')
    def toggle_reg_bonus(self, request):
        """
        Toggle the registration bonus for a user.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return self.handle_action_response(user,  "User Registraction Bonus Removed Successfully" if user.is_reg_balance_add else "User Registration Added Successfully")

    @action(detail=False, methods=['post'], url_path='toggle-min-balance')
    def toggle_user_min_balance(self, request):
        """
        Toggle the minimum balance requirement for a user.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return self.handle_action_response(user, "User Mininum Balance For Submission Disabled" if user.is_min_balance_for_submission_removed else "User Minimun Balance For Submission Enabled")

    @action(detail=False, methods=['post'], url_path='get_user_info')
    def get_user_info(self, request):
        """
        Get more User Infoamtion
        """
        serializer =  self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return self.handle_action_response(user, "User Info Retrieved Succussfully",AdminUserUpdateSerializer.UserProfileRetrieve)

    @action(detail=False, methods=['post'], url_path='toggle_user_active')
    def toggle_user_active(self,request):
        """
        Toggle user is active status
        """
        serializer =  self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return self.handle_action_response(user, "User has be Actived back" if user.is_active else "User has been deactivated successfully")
    
    @action(detail=False, methods=['post'], url_path='reset_user_account')
    def reset_user_account(self,request):
        """
        Reset the user Account 
        """
        serializer =  self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return self.handle_action_response(user, "User Account has been reset successfully")
    

    @action(detail=False, methods=['post'], url_path='update_credit_score')
    def update_credit_score(self,request):
        """
        Update the user credit score
        """
        serializer =  self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return self.handle_action_response(user, "User Credit score has been updated successfully")
    
class OnHoldViewSet(StandardResponseMixin,ModelViewSet):
    queryset = OnHoldPay.objects.all()
    serializer_class = OnHoldPaySerializer
    permission_classes = [IsSiteAdmin]


class AdminNegativeUserManagementViewSet(StandardResponseMixin,ModelViewSet):
    serializer_class = AdminNegativeUserSerializer.List
    permission_classes = [IsSiteAdmin]
    
    def get_queryset(self):
        return Game.objects.filter(is_active=True,played=False,special_product=True)

    def get_serializer_class(self):
        if self.action in ['retrieve', 'list']:
            return AdminNegativeUserSerializer.List
        return AdminNegativeUserSerializer.Create
    
    def handle_action_response(self, data, message="Action completed successfully.",override_serializer=None):
        """
        Centralized function to handle responses using UserProfile serializer.
        Returns a standardized response.
        """
        if not override_serializer:
            serializer = AdminNegativeUserSerializer.List(instance=data)
        else:
            serializer = override_serializer(instance=data)
        return self.standard_response(
                success=True,
                message=message,
                data=serializer.data,
                status_code=status.HTTP_200_OK,
            )

    def create(self,request):
        """
        Handles the creation of a negative game.
        """
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        game = serializer.save()
        create_admin_log(request,f"Added negative submission to user {game.user.username} ")
        return self.handle_action_response(game, "User Negative Submission Created Succussfully")
    

    def update(self, request, *args, **kwargs):
        """
        Handles updates for a negative game instance.
        """
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        updated_game = serializer.save()
        create_admin_log(request,f"Update negative submission for user {updated_game.user.username} ")
        return self.handle_action_response(updated_game, "User Negative Submission Created Succussfully")

    def destroy(self, request, *args, **kwargs):
        """
        delete the nagative game
        """
        instance = self.get_object()
        create_admin_log(request,f"Deleted the Negative User Submission for user {instance.user.username}")
        instance.delete()
        return self.standard_response(
                success=True,
                message="Negative Submission for user has been deleted Successfully",
                data=None,
                status_code=status.HTTP_204_NO_CONTENT,
            )
    

