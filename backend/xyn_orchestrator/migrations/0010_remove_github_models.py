from django.db import migrations


def remove_github_socialapps(apps, schema_editor):
    SocialApp = apps.get_model("socialaccount", "SocialApp")
    SocialAccount = apps.get_model("socialaccount", "SocialAccount")
    SocialToken = apps.get_model("socialaccount", "SocialToken")

    github_accounts = SocialAccount.objects.filter(provider="github")
    SocialToken.objects.filter(account__in=github_accounts).delete()
    github_accounts.delete()
    SocialApp.objects.filter(provider="github").delete()


class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0009_github_org_allow_login"),
        ("socialaccount", "0003_extra_data_default_dict"),
    ]

    operations = [
        migrations.RunPython(remove_github_socialapps, migrations.RunPython.noop),
        migrations.DeleteModel(name="GitHubRepoChunk"),
        migrations.DeleteModel(name="GitHubRepo"),
        migrations.DeleteModel(name="GitHubOrganization"),
        migrations.DeleteModel(name="GitHubConfig"),
    ]
