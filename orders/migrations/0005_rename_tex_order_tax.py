# Generated by Django 4.1.2 on 2023-01-16 11:56

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('orders', '0004_rename_phone_number_order_phone'),
    ]

    operations = [
        migrations.RenameField(
            model_name='order',
            old_name='tex',
            new_name='tax',
        ),
    ]