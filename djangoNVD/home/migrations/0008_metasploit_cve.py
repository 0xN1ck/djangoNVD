# Generated by Django 2.2.6 on 2020-01-09 12:35

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0007_capec_distinct'),
    ]

    operations = [
        migrations.CreateModel(
            name='metasploit_cve',
            fields=[
                ('id', models.IntegerField(primary_key=True, serialize=False)),
                ('way', models.TextField()),
                ('CVE_name', models.TextField()),
            ],
        ),
    ]
