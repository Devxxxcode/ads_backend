# Generated by Django 3.2.21 on 2024-11-19 03:23

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0005_alter_user_referral_code'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='last_connection',
            field=models.DateTimeField(blank=True, null=True, verbose_name='Last Connection'),
        ),
    ]
