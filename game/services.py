from django.utils.timezone import now, timedelta
from .models import Game, Product,generate_unique_rating_no
import random
from shared.helpers import get_settings,create_admin_notification,create_user_notification


class PlayGameService:
    """
    Service to handle the logic for playing a game and assigning the next game.
    """

    def __init__(self, user, total_number_can_play, wallet):
        self.user = user
        self.total_number_can_play = total_number_can_play
        self.wallet = wallet
        self.settings = get_settings()
        self.pack = wallet.package

    def check_can_user_play(self):
        """
        Check if the user is eligible to play a game.
        Returns a tuple: (can_play: bool, message: str)
        """
        if self.wallet.on_hold != 0:
            return False, "You have a pending transaction, please clear it to proceed."
        if not self.user.is_min_balance_for_submission_removed:
            min_balance = getattr(self.settings, 'minimum_balance_for_submissions', 100)
            if self.wallet.balance < min_balance:
                return False, f"You need a minimum of {min_balance} USD balnce to make a submission."
        cancel_play, messgae = self.user_has_completed_all_set_or_needs_reset()
        if cancel_play:
            return False,messgae
        return True, ""
    
    def get_ordinal(self,number):
        """
        Convert an integer into its ordinal representation.
        E.g., 1 -> '1st', 2 -> '2nd', 3 -> '3rd', etc.
        """
        if 10 <= number % 100 <= 20:
            suffix = "th"
        else:
            suffix = {1: "st", 2: "nd", 3: "rd"}.get(number % 10, "th")
        return f"{number}{suffix}"

    def user_has_completed_all_set_or_needs_reset(self):
        """
        Check if the user has completed all sets or needs to reset.
        Returns a tuple: (has_completed: bool, message: str)
        """
        set_number = self.get_ordinal(self.user.number_of_submission_set_today + 1)
        if Game.count_games_played_today(self.user) >= self.total_number_can_play and self.pack.number_of_set > self.user.number_of_submission_set_today: 
            return True, f"Good job!!!. The {set_number} set of the submission has been completed. Kindly request for the next sets."
        if Game.count_games_played_today(self.user) >= self.total_number_can_play and self.pack.number_of_set <= self.user.number_of_submission_set_today: 
            return True, f"Good job!!!. You have completed all {self.user.number_of_submission_set_today + 1} submission sets for today!!!"
        return False,""
    
    def check_can_user_play_pending_game(self):
        """
        Check if the user is eligible to play a pending game.
        Returns a tuple: (can_play: bool, message: str)
        """
        if self.wallet.on_hold != 0:
            return False, "You have a pending transaction, please clear it to proceed."
        if Game.count_games_played_today(self.user) >= self.total_number_can_play:
            return False, "You have reached the maximum number of submissions you can make today, upgrade you package"
        return True, ""

    def get_active_game(self):
        """
        Retrieve the user's active game.
        Returns a tuple: (game: Game or None, error: str)
        """
        pending_game = Game.objects.filter(user=self.user, played=False,pending=True,is_active=True).first()
        if pending_game:
            return pending_game,""
        special_game = Game.objects.filter(user=self.user, played=False,special_product=True,game_number=(Game.count_games_played_today(self.user)+1),is_active=True).first()
        if special_game:
            return special_game,""
        active_game = Game.objects.filter(user=self.user, played=False,is_active=True).first()
        if active_game:
            return active_game, ""

        # If no active game exists, try to assign a new one
        return self.assign_next_game()

    def mark_game_as_played(self, game, rating_score, comment):
        """
        Mark the current active game as played and update it with a rating and comment.
        """
        amount = game.amount
        commission = game.commission

        if game.pending:
            self.wallet.credit(commission)
            self.wallet.credit_commission(commission)
        else:
            if self.wallet.balance < amount and game.special_product:
                game.pending = True
                game.save()
                self.wallet.on_hold = self.wallet.balance - amount
                self.wallet.save()
                return False, "Insufficient balance to make this submission."

            self.wallet.credit(commission)
            self.wallet.credit_commission(commission)

        game.rating_score = rating_score
        game.comment = comment
        game.played = True
        game.pending = False
        self.user.number_of_submission_today +=1
        self.user.today_profit +=commission
        self.user.save()
        if self.user.number_of_submission_today >= self.total_number_can_play:
            self.user.number_of_submission_set_today += 1
            self.user.save()
            set_number = self.get_ordinal(self.user.number_of_submission_set_today + 1)
            create_admin_notification("Worker Set Completed",f"{self.user.username} has completed all submissions in the {set_number} set, You can proceed to reset account")
            if self.user.number_of_submission_set_today <  self.pack.number_of_set:
                create_user_notification(self.user,"Submission Completed",f"Good job!!!. The {set_number} set of the submission has been completed. Kindly request for the next sets.")
            
        if self.user.number_of_submission_set_today >=  self.pack.number_of_set:
            create_user_notification(self.user,"Good job!!! Submission Set Completed","You have completed all your submissions set for today!!!!!!")
            create_admin_notification("Worker Set Completed",f"{self.user.username} has completed all submissions set for today")
        self.user.save()
        game.save()

        return True, ""


    def assign_next_game(self):
        """
        Assign the next game for the user with one or two products they haven't played today.
        Set the game amount and commission based on the selected products.
        Returns a tuple: (game: Game or None, message: str)
        """
        start_of_day = now().replace(hour=0, minute=0, second=0, microsecond=0)
        end_of_day = start_of_day + timedelta(days=1)

        # Get all products the user has played today
        played_products_today = Game.objects.filter(
            user=self.user,
            is_active=True,
            created_at__gte=start_of_day,
            created_at__lt=end_of_day
        ).values_list('products__id', flat=True)

        # Get products the user hasn't played today
        available_products = Product.objects.exclude(id__in=played_products_today)

        if not available_products.exists():
            return None, "No new submission available for you. Check back later"

        affordable_products = [
            product for product in available_products
            if product.price <= self.wallet.balance
        ]

        if not affordable_products:
            return None, "No new submission available within your level, Update your current level"

        # Randomly select 1 or 2 products from the available list
        product_count = random.choice([1, 1])
        selected_products = random.sample(list(affordable_products), min(product_count, len(affordable_products)))

        # Calculate the total amount and commission
        total_amount = sum(product.price for product in selected_products)
        if self.wallet.package:
            commission_percentage = self.wallet.package.profit_percentage
        else:
            commission_percentage = 0.5  # Default to 20% if no package is available

        commission = (total_amount * commission_percentage) / 100

        # Create a new game instance
        new_game = Game.objects.create(
            user=self.user,
            played=False,
            amount=total_amount,
            commission=commission,
            is_active=True,
            rating_no=generate_unique_rating_no()
        )

        # Associate the selected products with the new game
        new_game.products.set(selected_products)
        new_game.save()

        return new_game, ""

    def play_game(self, rating_score, comment):
        """
        Main method to mark the active game as played and assign the next game.
        Returns a tuple: (game: Game or None, message: str)
        """

        # Retrieve the active game or assign a new one
        active_game, error = self.get_active_game()
        if not active_game:
            return None, error
        
        if active_game.pending:
            # Check if the user is eligible to play
            can_play, message = self.check_can_user_play_pending_game()
            if not can_play:
                return None, message
        else:
            # Check if the user is eligible to play
            can_play, message = self.check_can_user_play()
            if not can_play:
                return None, message

        # Mark the current active game as played with rating and comment
        played,error_playing = self.mark_game_as_played(active_game, rating_score, comment)

        # Assign the next game
        next_game, error = self.get_active_game()
        if error:
            return None, error

        return next_game, "Submission  successfull!" if played else error_playing

    def play_pending_game(self, rating_score, comment):
        """
        Main method to mark the active game as played and assign the next game.
        Returns a tuple: (game: Game or None, message: str)
        """
        # Check if the user is eligible to play
        can_play, message = self.check_can_user_play_pending_game()
        if not can_play:
            return None, message

        # Retrieve the active game or assign a new one
        active_game, error = self.get_active_game()
        if error:
            return None, error

        # Mark the current active game as played with rating and comment
        played,error_playing = self.mark_game_as_played(active_game, rating_score, comment)

        # Assign the next game
        next_game, error = self.get_active_game()
        if error:
            return None, error

        return next_game, "Submission successfull!" if played else error_playing

