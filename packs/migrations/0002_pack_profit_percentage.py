# Generated by Django 3.2.21 on 2024-11-23 22:43

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('packs', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='pack',
            name='profit_percentage',
            field=models.DecimalField(decimal_places=2, default=0.0, max_digits=5, validators=[django.core.validators.MinValueValidator(0.0), django.core.validators.MaxValueValidator(100.0)], verbose_name='Profit Per Mission'),
        ),
    ]
