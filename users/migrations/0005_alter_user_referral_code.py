# Generated by Django 3.2.21 on 2024-11-15 16:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0004_auto_20241115_1434'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='referral_code',
            field=models.CharField(editable=False, max_length=6),
        ),
    ]
