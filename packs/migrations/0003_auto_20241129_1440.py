# Generated by Django 3.2.21 on 2024-11-29 14:40

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('packs', '0002_pack_profit_percentage'),
    ]

    operations = [
        migrations.AddField(
            model_name='pack',
            name='payment_bonus',
            field=models.DecimalField(decimal_places=2, default=0.0, max_digits=10, validators=[django.core.validators.MinValueValidator(0.0)], verbose_name='Payment Bonus'),
        ),
        migrations.AddField(
            model_name='pack',
            name='payment_limit_to_trigger_bonus',
            field=models.DecimalField(decimal_places=2, default=0.0, max_digits=10, validators=[django.core.validators.MinValueValidator(0.0)], verbose_name='Payment Limit for bonus to be triggered'),
        ),
    ]
