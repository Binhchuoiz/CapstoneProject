# Generated by Django 5.0.3 on 2024-03-19 14:16

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('firstapp', '0004_rename_con_id_affected_con_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='descriptions',
            name='value',
            field=models.CharField(default='', max_length=9000, null=True),
        ),
        migrations.AlterField(
            model_name='solutions',
            name='value',
            field=models.CharField(default='', max_length=9000, null=True),
        ),
    ]
