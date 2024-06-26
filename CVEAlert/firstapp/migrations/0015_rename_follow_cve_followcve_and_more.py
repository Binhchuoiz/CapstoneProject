# Generated by Django 5.0.3 on 2024-04-25 12:12

from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('firstapp', '0014_cve_assignershortname_cve_title_and_more'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RenameModel(
            old_name='Follow_CVE',
            new_name='FollowCVE',
        ),
        migrations.RenameModel(
            old_name='Follow_Product',
            new_name='FollowProduct',
        ),
        migrations.RenameModel(
            old_name='Products_Versions',
            new_name='ProductsVersions',
        ),
        migrations.RenameField(
            model_name='cve',
            old_name='assigner_Org_Id',
            new_name='assigner_org_id',
        ),
        migrations.RenameField(
            model_name='cve',
            old_name='assignerShortName',
            new_name='assigner_short_name',
        ),
        migrations.RenameField(
            model_name='problemtypes',
            old_name='cweId',
            new_name='cwe_id',
        ),
        migrations.RemoveField(
            model_name='cve',
            name='provider_Metadata',
        ),
        migrations.AddField(
            model_name='descriptions',
            name='lang',
            field=models.CharField(default='en', max_length=10),
        ),
        migrations.AddField(
            model_name='problemtypes',
            name='lang',
            field=models.CharField(default='en', max_length=10),
        ),
        migrations.AlterField(
            model_name='cvssv20',
            name='base_score',
            field=models.FloatField(default=0.0, null=True),
        ),
        migrations.AlterField(
            model_name='cvssv30',
            name='base_score',
            field=models.FloatField(default=0.0, null=True),
        ),
        migrations.AlterField(
            model_name='cvssv31',
            name='base_score',
            field=models.FloatField(default=0.0, null=True),
        ),
    ]
