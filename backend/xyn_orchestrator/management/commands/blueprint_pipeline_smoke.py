import mimetypes
import time
import uuid
from pathlib import Path

from django.core.files.base import File
from django.core.management.base import BaseCommand, CommandError

from xyn_orchestrator.blueprints import _async_mode, _enqueue_job
from xyn_orchestrator.models import BlueprintDraftSession, DraftSessionVoiceNote, VoiceNote
from xyn_orchestrator.services import generate_blueprint_draft, revise_blueprint_draft, transcribe_voice_note


class Command(BaseCommand):
    help = "Smoke test the voice note -> transcript -> blueprint draft pipeline."

    def add_arguments(self, parser):
        parser.add_argument("--audio", required=True, help="Path to an audio file to upload.")
        parser.add_argument("--session-name", default="Smoke test session")
        parser.add_argument("--language-code", default="en-US")
        parser.add_argument("--mime-type", default=None)
        parser.add_argument(
            "--blueprint-kind",
            choices=["solution", "module", "bundle"],
            default="solution",
            help="Blueprint kind for the draft session.",
        )
        parser.add_argument("--timeout", type=int, default=300)
        parser.add_argument("--poll-interval", type=int, default=5)
        parser.add_argument("--revision-instruction", default=None)
        parser.add_argument(
            "--allow-inprocess",
            action="store_true",
            help="Allow running the in-process fallback instead of Redis.",
        )

    def handle(self, *args, **options):
        audio_path = Path(options["audio"]).expanduser()
        if not audio_path.exists():
            raise CommandError(f"Audio file not found: {audio_path}")

        mode = _async_mode()
        if mode != "redis" and not options["allow_inprocess"]:
            raise CommandError(
                "Async mode is not redis. Set XYENCE_ASYNC_JOBS_MODE=redis or pass --allow-inprocess."
            )

        mime_type = options["mime_type"] or mimetypes.guess_type(audio_path.name)[0] or "application/octet-stream"

        session = BlueprintDraftSession.objects.create(
            name=options["session_name"],
            status="drafting",
            blueprint_kind=options["blueprint_kind"],
        )
        voice_note = VoiceNote.objects.create(
            title=f"Smoke test voice note {session.id}",
            mime_type=mime_type,
            language_code=options["language_code"],
            status="uploaded",
        )
        with audio_path.open("rb") as handle:
            voice_note.audio_file.save(audio_path.name, File(handle), save=True)
        DraftSessionVoiceNote.objects.create(draft_session=session, voice_note=voice_note, ordering=0)

        self.stdout.write(f"Created draft session {session.id}")
        self.stdout.write(f"Created voice note {voice_note.id}")

        self._enqueue_transcription(voice_note, mode)
        self._wait_for_voice_note(voice_note, options["timeout"], options["poll_interval"])

        self._enqueue_draft_generation(session, mode)
        self._wait_for_session(session, options["timeout"], options["poll_interval"])

        instruction = options["revision_instruction"]
        if instruction:
            self._enqueue_revision(session, instruction, mode)
            self._wait_for_session(session, options["timeout"], options["poll_interval"])

        session.refresh_from_db()
        self.stdout.write("Draft session status: %s" % session.status)
        self.stdout.write("Job id: %s" % (session.job_id or "(none)"))
        self.stdout.write("Validation errors: %s" % (session.validation_errors_json or []))

    def _enqueue_transcription(self, voice_note: VoiceNote, mode: str) -> None:
        if mode == "redis":
            voice_note.status = "queued"
            job_id = _enqueue_job("xyn_orchestrator.worker_tasks.transcribe_voice_note", str(voice_note.id))
        else:
            voice_note.status = "transcribing"
            job_id = str(uuid.uuid4())
            transcribe_voice_note(str(voice_note.id))
        voice_note.job_id = job_id
        voice_note.error = ""
        voice_note.save(update_fields=["status", "job_id", "error"])
        self.stdout.write(f"Enqueued transcription job {job_id}")

    def _enqueue_draft_generation(self, session: BlueprintDraftSession, mode: str) -> None:
        if mode == "redis":
            session.status = "queued"
            job_id = _enqueue_job("xyn_orchestrator.worker_tasks.generate_blueprint_draft", str(session.id))
        else:
            session.status = "drafting"
            job_id = str(uuid.uuid4())
            generate_blueprint_draft(str(session.id))
        session.job_id = job_id
        session.last_error = ""
        session.save(update_fields=["status", "job_id", "last_error"])
        self.stdout.write(f"Enqueued draft generation job {job_id}")

    def _enqueue_revision(self, session: BlueprintDraftSession, instruction: str, mode: str) -> None:
        if mode == "redis":
            session.status = "queued"
            job_id = _enqueue_job("xyn_orchestrator.worker_tasks.revise_blueprint_draft", str(session.id), instruction)
        else:
            session.status = "drafting"
            job_id = str(uuid.uuid4())
            revise_blueprint_draft(str(session.id), instruction)
        session.job_id = job_id
        session.last_error = ""
        session.save(update_fields=["status", "job_id", "last_error"])
        self.stdout.write(f"Enqueued revision job {job_id}")

    def _wait_for_voice_note(self, voice_note: VoiceNote, timeout: int, poll_interval: int) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            voice_note.refresh_from_db()
            if voice_note.status in {"transcribed", "failed"}:
                break
            time.sleep(poll_interval)
        if voice_note.status != "transcribed":
            raise CommandError(f"Transcription did not complete: {voice_note.status} ({voice_note.error})")
        self.stdout.write("Transcription complete")

    def _wait_for_session(self, session: BlueprintDraftSession, timeout: int, poll_interval: int) -> None:
        terminal = {"ready", "ready_with_errors", "failed"}
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            session.refresh_from_db()
            if session.status in terminal:
                break
            time.sleep(poll_interval)
        if session.status == "failed":
            raise CommandError(f"Draft session failed: {session.last_error}")
        if session.status not in terminal:
            raise CommandError("Draft session did not complete before timeout")
        self.stdout.write("Draft session complete")
