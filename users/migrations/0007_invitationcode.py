# Generated by Django 3.2.21 on 2024-11-20 05:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('users', '0006_user_last_connection'),
    ]

    operations = [
        migrations.CreateModel(
            name='InvitationCode',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('Invitation_code', models.CharField(editable=False, max_length=6)),
                ('is_used', models.BooleanField(default=False)),
            ],
        ),
    ]
