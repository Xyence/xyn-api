import os

from django.conf import settings
from django.db import migrations


def create_google_socialapp(apps, schema_editor):
    SocialApp = apps.get_model("socialaccount", "SocialApp")
    Site = apps.get_model("sites", "Site")

    site_id = getattr(settings, "SITE_ID", 1)
    site = Site.objects.filter(id=site_id).first()
    if not site:
        return

    client_id = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
    secret = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
    if client_id and secret:
        app, _ = SocialApp.objects.update_or_create(
            provider="google",
            defaults={
                "name": "Google",
                "client_id": client_id,
                "secret": secret,
                "key": "",
            },
        )
        app.sites.add(site)



class Migration(migrations.Migration):
    dependencies = [
        ("xyn_orchestrator", "0007_site_domain"),
        ("sites", "0002_alter_domain_unique"),
        ("socialaccount", "0003_extra_data_default_dict"),
    ]

    operations = [
        migrations.RunPython(create_google_socialapp, migrations.RunPython.noop),
    ]
