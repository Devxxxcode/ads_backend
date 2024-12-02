# Generated by Django 3.2.21 on 2024-11-20 05:53

from django.db import migrations, models
import django.utils.timezone


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0008_rename_invitation_code_invitationcode_invitation_code'),
    ]

    operations = [
        migrations.AddField(
            model_name='invitationcode',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),
    ]