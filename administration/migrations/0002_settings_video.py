# Generated by Django 3.2.21 on 2024-11-23 23:57

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('administration', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='settings',
            name='video',
            field=models.FileField(blank=True, null=True, upload_to='videos/', verbose_name='Video'),
        ),
    ]
