import os

from django.conf import settings
from django.db import migrations


def set_site_domain(apps, schema_editor):
    Site = apps.get_model("sites", "Site")
    site_id = getattr(settings, "SITE_ID", 1)

    env_domain = os.environ.get("DJANGO_SITE_DOMAIN", "").strip()
    env_hosts = os.environ.get("DJANGO_ALLOWED_HOSTS", "").split(",")
    host_domain = next((host.strip() for host in env_hosts if host.strip() and host.strip() != "*"), "")
    domain = env_domain or host_domain or "xyence.io"
    name = os.environ.get("DJANGO_SITE_NAME", "").strip() or domain

    Site.objects.update_or_create(
        id=site_id,
        defaults={"domain": domain, "name": name},
    )


class Migration(migrations.Migration):
    dependencies = [
        ("articles", "0006_ckeditor5"),
        ("sites", "0002_alter_domain_unique"),
    ]

    operations = [
        migrations.RunPython(set_site_domain, migrations.RunPython.noop),
    ]
