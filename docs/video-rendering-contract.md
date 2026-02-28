# Video Rendering Contract

Xyn produces a governed `render_package` artifact from explainer inputs. Platform settings choose how that package is rendered.

## Rendering Modes

- `export_package_only`: no remote render, package remains downloadable.
- `render_via_adapter`: invoke a registered adapter with a canonical adapter config artifact.
- `render_via_endpoint`: call an external HTTP renderer endpoint directly.
- `render_via_model_config`: reserved feature-flagged mode (`VIDEO_RENDER_DIRECT_MODEL`).

## Endpoint Mode Payload

When `render_via_endpoint` is selected, the renderer contract is:

`POST {endpoint_url}/render`

```json
{
  "render_package_id": "<artifact-id>",
  "render_package_hash": "<sha256>",
  "callback_url": "<xyn callback>",
  "options": {}
}
```

Adapters may add provider-specific fields, but this envelope remains stable.

## Adapter Config Artifacts

`video_adapter_config` artifacts store provider runtime config (credential refs, model ids, caps/defaults) and are governed with artifact lifecycle + ledger updates.

Seeded config included:

- slug: `google-veo-prod`
- adapter: `google_veo`
- provider model: `veo-3.1`

## Direct Google Veo Adapter

When `render_via_adapter` is selected and `adapter_id=google_veo`, Xyn calls Google directly:

1. Submit generation request to `https://generativelanguage.googleapis.com/v1beta/models/{provider_model_id}:generateVideos` (fallback `:predictLongRunning`).
2. Poll returned operation until `done=true`.
3. Extract video URIs from operation response and store as render assets.

Credential expectations:

- `credential_ref` resolves to a secret containing either:
  - a raw Google API key (`AIza...`), or
  - JSON with `api_key` / `apiKey` / `key`.

If no video URI is returned, render is marked failed and export package remains as fallback artifact.
