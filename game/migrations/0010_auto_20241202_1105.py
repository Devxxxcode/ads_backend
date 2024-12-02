# Generated by Django 3.2.21 on 2024-12-02 11:05

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('wallet', '0005_onholdpay'),
        ('game', '0009_auto_20241202_0808'),
    ]

    operations = [
        migrations.AddField(
            model_name='game',
            name='on_hold',
            field=models.ForeignKey(blank=True, help_text='Reference to the on-hold payment associated with this game.', null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='negative_games', to='wallet.onholdpay'),
        ),
        migrations.DeleteModel(
            name='NegativeUser',
        ),
    ]
