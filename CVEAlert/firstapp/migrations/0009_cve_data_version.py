# Generated by Django 5.0.3 on 2024-03-20 14:37

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('firstapp', '0008_remove_cve_data_version_alter_cve_date_publish_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='cve',
            name='data_version',
            field=models.CharField(default='', max_length=255),
        ),
    ]