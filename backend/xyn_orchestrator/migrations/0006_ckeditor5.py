from django.db import migrations
import django_ckeditor_5.fields


class Migration(migrations.Migration):
    dependencies = [
        ("articles", "0005_github_orgs"),
    ]

    operations = [
        migrations.AlterField(
            model_name="article",
            name="body",
            field=django_ckeditor_5.fields.CKEditor5Field("body", config_name="default"),
        ),
        migrations.AlterField(
            model_name="articleversion",
            name="body",
            field=django_ckeditor_5.fields.CKEditor5Field("body", config_name="default"),
        ),
    ]
