# Generated by Django 5.0.3 on 2024-05-03 15:34

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('firstapp', '0017_alter_cvssv20_base_score_alter_cvssv30_base_score_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='problemtypes',
            name='con',
        ),
        migrations.CreateModel(
            name='ProblemTypes_CVE',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('con', models.ForeignKey(blank=True, default=None, on_delete=django.db.models.deletion.CASCADE, related_name='problemTypes_cves', to='firstapp.cve')),
                ('problemTypes', models.ForeignKey(blank=True, default=None, on_delete=django.db.models.deletion.CASCADE, related_name='cves_problemTypes', to='firstapp.problemtypes')),
            ],
        ),
    ]
