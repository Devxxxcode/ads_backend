# Generated by Django 3.2.21 on 2024-12-30 12:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0013_user_today_profit'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='current_referral_bonus',
            field=models.DecimalField(blank=True, decimal_places=2, default=0.0, max_digits=12, null=True, verbose_name='The current referral bonus earned by user beefore notifcation'),
        ),
    ]