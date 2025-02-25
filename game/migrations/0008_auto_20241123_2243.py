# Generated by Django 3.2.21 on 2024-11-23 22:43

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('game', '0007_auto_20241120_0644'),
    ]

    operations = [
        migrations.AddField(
            model_name='game',
            name='game_number',
            field=models.IntegerField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name='game',
            name='pending',
            field=models.BooleanField(default=False),
        ),
    ]
