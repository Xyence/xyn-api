from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0008_google_socialapp"),
    ]

    operations = [
        migrations.AddField(
            model_name="githuborganization",
            name="allow_login",
            field=models.BooleanField(default=False),
        ),
    ]
