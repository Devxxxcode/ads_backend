from rest_framework import serializers
from .models import Product,Game
from django.contrib.auth import get_user_model
from wallet.models import OnHoldPay
import random
from decimal import Decimal
from users.serializers import AdminUserUpdateSerializer

User = get_user_model()

class OnHoldPaySerializer(serializers.ModelSerializer):
    class Meta:
        model = OnHoldPay
        fields = "__all__"
        ref_name = "OnHoldPaySerializer game"


class ProductSerializer(serializers.ModelSerializer):
    """
    Serializer for the Product model with custom validation.
    """

    class Meta:
        model = Product
        fields = [
            'id',
            'name',
            'price',
            'image',
            'rating_no',
            'date_created',
        ]
        read_only_fields = ['rating_no', 'date_created']

    def validate_price(self, value):
        """
        Ensure the price is a positive number.
        """
        if value <= 0:
            raise serializers.ValidationError("Price must be greater than 0.")
        return value




class ProductList(serializers.ModelSerializer):
    """
    Serializer for listing products associated with a game.
    """
    class Meta:
        model = Product  # Fixed to reference the Product model
        fields = ['id', 'name', 'image', 'price', 'rating_no']


class GameSerializer:
    """
    Serializer container for games.
    """

    class PlayGameRequestSerializer(serializers.Serializer):
        """
        Serializer for the play game request payload.
        """
        rating_score = serializers.IntegerField(required=True)
        comment = serializers.CharField(required=False, allow_blank=True)


    class Retrieve(serializers.ModelSerializer):
        """
        Serializer for retrieving game details, including products and limits.
        """
        total_number_can_play = serializers.SerializerMethodField()
        current_number_count = serializers.SerializerMethodField()
        products = ProductList(many=True)  # Correctly reference ProductList serializer

        class Meta:
            model = Game
            fields = [
                'id', 
                'products', 
                'amount', 
                'commission', 
                'total_number_can_play', 
                'current_number_count', 
                'rating_score',
                'comment',
                'special_product',
                'created_at',
                'rating_no',
                'game_number',
                'pending',
            ]
            ref_name = "Game Retrieve" 
            extra_kwargs = {
            'rating_score': {'write_only': True},
            'comment': {'write_only': True},
        }
        
        def get_total_number_can_play(self, obj):
            """
            Retrieve the total number of games the user can play.
            This should be passed in the serializer context.
            """
            return self.context.get('total_number_can_play', 0)

        def get_current_number_count(self, obj):
            """
            Retrieve the current number of games played by the user today.
            This should be passed in the serializer context.
            """
            return self.context.get('current_number_count', 0)
        
    class List(serializers.ModelSerializer):
        products = ProductList(many=True) 
        class Meta:
            model = Game
            fields = [
                'id', 
                'products', 
                'amount', 
                'commission', 
                'rating_score',
                'comment',
                'special_product',
                'updated_at',
                'rating_no',
                'pending',
            ]
            ref_name = "Game Retrieve" 


class AdminNegativeUserSerializer:

    class Create(serializers.ModelSerializer):
        user = serializers.PrimaryKeyRelatedField(queryset=User.objects.all(),required=True)
        on_hold = serializers.PrimaryKeyRelatedField(queryset=OnHoldPay.objects.filter(is_active=True),required=True)
        number_of_negative_product = serializers.IntegerField(required=True,min_value=0,max_value=3,help_text="Number of negative products must be between 0 and 3.")
        rank_appearance = serializers.IntegerField(required=True,min_value=0)
        
        class Meta:
            model = Game
            fields = ['user','on_hold','number_of_negative_product','rank_appearance']
            ref_name = "Negative User Create"

        def save(self):
            """Create or update a negative game for the user"""
            user = self.validated_data['user']
            profit_percentage = user.wallet.package.profit_percentage
            on_hold = self.validated_data['on_hold']
            number_of_negative_product = self.validated_data.get('number_of_negative_product', self.instance.products.count() if self.instance else 0)
            rank_appearance = self.validated_data.get('rank_appearance', self.instance.game_number if self.instance else None)
            products = Product.objects.order_by('?')[:number_of_negative_product]
            on_hold_min = float(on_hold.min_amount)  # Convert Decimal to float
            on_hold_max = float(on_hold.max_amount)  # Convert Decimal to float
            balance = user.wallet.balance

            # Generate a random amount between min and max
            random_amount = random.uniform(on_hold_min, on_hold_max)
            amount = balance + random_amount
            amount = Decimal(round(random_amount, 2))  # Convert back to Decimal

            # Calculate commission
            commission = (amount * Decimal(profit_percentage) / Decimal(100)) * Decimal(5)

            if self.instance:
                # Update existing instance
                self.instance.user = user
                self.instance.on_hold = on_hold
                self.instance.game_number = rank_appearance
                self.instance.amount = amount
                self.instance.commission = commission
                self.instance.special_product = True
                self.instance.is_active = True
                self.instance.products.set(products)
                self.instance.save()
                return self.instance
            else:
                # Create a new instance
                game = Game.objects.create(
                    user=user,
                    on_hold=on_hold,
                    game_number=rank_appearance,
                    played=False,
                    amount=amount,
                    commission=commission,
                    special_product=True,
                    is_active=True,
                )
                game.products.set(products)
                return game



    class List(serializers.ModelSerializer):
        user = AdminUserUpdateSerializer.UserProfileRetrieve(read_only=True)
        number_of_negative_product = serializers.SerializerMethodField(read_only=True)
        rank_appearance = serializers.SerializerMethodField(read_only=True)
        on_hold = OnHoldPaySerializer(read_only=True)
        ref_name = "Negative User List"
        class Meta:
            model = Game
            fields = ['id','user','on_hold','number_of_negative_product','rank_appearance','is_active']
            ref_name = "Negative User List"

        def get_number_of_negative_product(self,obj):
            number_of_negative_product = obj.products.count()
            return number_of_negative_product

        def get_rank_appearance(self,obj):
            return obj.game_number