# Generated by Django 5.0.3 on 2024-05-02 15:02

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('firstapp', '0016_rename_followcve_follow_cve_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='cvssv20',
            name='base_score',
            field=models.FloatField(default='', null=True),
        ),
        migrations.AlterField(
            model_name='cvssv30',
            name='base_score',
            field=models.FloatField(default='', null=True),
        ),
        migrations.AlterField(
            model_name='cvssv31',
            name='base_score',
            field=models.FloatField(default='', null=True),
        ),
    ]
