# Generated by Django 4.1.2 on 2022-12-20 10:08

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('category', '0003_alter_category_options'),
    ]

    operations = [
        migrations.AlterField(
            model_name='category',
            name='slug',
            field=models.SlugField(max_length=100, unique=True),
        ),
    ]
