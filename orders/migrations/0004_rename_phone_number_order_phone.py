# Generated by Django 4.1.2 on 2023-01-16 11:31

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('orders', '0003_order_order_total'),
    ]

    operations = [
        migrations.RenameField(
            model_name='order',
            old_name='phone_number',
            new_name='phone',
        ),
    ]
