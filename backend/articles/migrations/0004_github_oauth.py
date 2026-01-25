from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):
    dependencies = [
        ("articles", "0003_github_context"),
        ("socialaccount", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="githubconfig",
            name="social_account",
            field=models.ForeignKey(blank=True, null=True, on_delete=django.db.models.deletion.SET_NULL, to="socialaccount.socialaccount"),
        ),
    ]
