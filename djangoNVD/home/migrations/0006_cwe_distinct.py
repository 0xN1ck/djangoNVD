# Generated by Django 2.2.7 on 2019-12-25 07:05

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('home', '0005_att_ck'),
    ]

    operations = [
        migrations.CreateModel(
            name='CWE_distinct',
            fields=[
                ('id', models.IntegerField(primary_key=True, serialize=False)),
                ('CWE_name', models.TextField()),
            ],
        ),
    ]