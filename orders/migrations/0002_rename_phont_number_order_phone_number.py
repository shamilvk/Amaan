# Generated by Django 4.1.4 on 2023-01-16 07:27

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('orders', '0001_initial'),
    ]

    operations = [
        migrations.RenameField(
            model_name='order',
            old_name='phont_number',
            new_name='phone_number',
        ),
    ]
