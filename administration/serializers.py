from rest_framework import serializers
from .models import Settings,Event
from finances.models import Deposit
from shared.helpers import get_settings
from users.models import Invitation
# from users.serializers import UserPartialSerilzer
from shared.helpers import create_user_notification
from django.contrib.auth import get_user_model

User = get_user_model()

class SettingsSerializer(serializers.ModelSerializer):
    class Meta:
        model = Settings
        exclude = ['id']

    def to_representation(self, instance):
        """
        Customize the representation of the video field to return the .url.
        """
        representation = super().to_representation(instance)
        # Replace the video field with its URL
        if instance.video:
            representation['video'] = instance.video.url
        return representation


class SettingsVideoSerializer(serializers.ModelSerializer):
    """
    Serializer for updating the video field in the Settings model.
    """
    
    class Meta:
        model = Settings
        fields = ['video']  # Include only the video field

    def to_representation(self, instance):
        """
        Customize the representation of the video field to return the .url.
        """
        representation = super().to_representation(instance)
        # Replace the video field with its URL
        if instance.video:
            representation['video'] = instance.video.url
        return representation

    def validate_video(self, value):
        if not value.name.lower().endswith(('.mp4', '.avi', '.mov', '.mkv')):
            raise serializers.ValidationError("The uploaded file is not a valid video format.")
        return value

class UserPartialSerilzer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "email",
            "last_name",
            "first_name",
            "is_active"
        ] 

class DepositSerializer:
    """
    Container for different Deposit serializers used in various actions.
    """

    class List(serializers.ModelSerializer):
        """
        Serializer for listing deposits.
        """
        user = UserPartialSerilzer(read_only=True)
        class Meta:
            model = Deposit
            fields = "__all__"
            ref_name = "Deposit - List"

    class UpdateStatus(serializers.ModelSerializer):
        """
        Serializer for updating the status of a deposit.
        """
        transactional_password = serializers.CharField(write_only=True)

        class Meta:
            model = Deposit
            fields = [
                "status",
                "transactional_password",
            ]
            ref_name = "Deposit - UpdateStatus"

        def validate_transactional_password(self, value):
            """
            Validate the transactional password from the user.
            """
            user = self.context.get("request").user
            if user.transactional_password != value:
                raise serializers.ValidationError("Invalid transactional password.")
            return value

        def validate_status(self, value):
            """
            Validate the status field.
            """
            allowed_statuses = ["Pending", "Confirmed", "Rejected"]
            if value not in allowed_statuses:
                raise serializers.ValidationError(f"Invalid status: {value}. Allowed: {allowed_statuses}")
            return value

        def update(self, instance, validated_data):
            """
            Update the deposit status and adjust the user's wallet balance based on the status transition.
            """
            old_status = instance.status
            new_status = validated_data.get("status")

            # Update the deposit instance
            instance.status = new_status
            instance.save()

            user = instance.user

            self.adjust_wallet_balance(
                user=instance.user,
                amount=instance.amount,
                old_status=old_status,
                new_status=new_status,
            )

            return instance

        def adjust_wallet_balance(self, user, amount, old_status, new_status):
            """
            Adjust the user's wallet balance based on status changes.
            """
            if old_status != "Confirmed" and new_status == "Confirmed":
                # Increment wallet balance when status changes to Confirmed
                user.wallet.balance += amount
                user.wallet.save()
                self.handle_referral_bonus(user,amount)
                print(f"Wallet increased: User {user.id} balance is now {user.wallet.balance}")

            elif old_status == "Confirmed" and new_status != "Confirmed":
                # Decrement wallet balance when status changes from Confirmed
                user.wallet.balance -= amount
                user.wallet.save()
                print(f"Wallet decreased: User {user.id} balance is now {user.wallet.balance}")

        def handle_referral_bonus(user, amount):
            """
            Check if the user has an associated invitation and award the referral bonus if applicable.
            """
            try:
                # Retrieve the invitation for the user
                invitation = user.invitation  # Access the Invitation instance associated with the user
                if not invitation.received_bonus:
                    # Retrieve settings to calculate the bonus percentage
                    settings = get_settings()
                    bonus_percentage = settings.percentage_of_sponsors
                    bonus_amount = amount * (bonus_percentage / 100)

                    # Award the referral bonus to the referrer
                    referral = invitation.referral
                    referral.wallet.balance += bonus_amount
                    referral.wallet.save()

                    # Mark the bonus as received
                    invitation.received_bonus = True
                    invitation.save()
                    create_user_notification(referral,"Referral Bonus",f"You have recieved a referral bonus of {bonus_amount:.2f}, Your current balance is {referral.wallet.balance}")
                    print(f"Referral bonus of {bonus_amount:.2f} awarded to user {referral.username} (ID: {referral.id}).")
            except Invitation.DoesNotExist:
                # Handle case where no invitation is found
                print(f"No invitation found for user {user.username}.")


class EventSerializer(serializers.ModelSerializer):
    created_by = UserPartialSerilzer(read_only=True)
    class Meta:
        model = Event
        fields = ['id', 'name', 'description', 'image', 'is_active', 'created_at','created_by']
        read_only_fields = ['created_at','created_by']

    def save(self, **kwargs):
        """
        Automatically set the `created_by` field to the currently logged-in user for both creation and update.
        """
        kwargs['created_by'] = self.context['request'].user
        return super().save(**kwargs)