from django.apps import AppConfig
import os
import sys


class XynOrchestratorConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "xyn_orchestrator"
    label = "xyn_orchestrator"

    def ready(self) -> None:
        if os.environ.get("XYENCE_BOOTSTRAP_DISABLE", "").strip() == "1":
            return
        argv = " ".join(sys.argv).lower()
        if any(cmd in argv for cmd in ("migrate", "makemigrations", "collectstatic", "shell", "test", "seed_packs")):
            return
        try:
            from xyn_orchestrator.instances.bootstrap import bootstrap_instance_registration
            from xyn_orchestrator.seeds import auto_apply_core_seed_packs

            bootstrap_instance_registration()
            auto_apply_core_seed_packs()
        except Exception:
            return
