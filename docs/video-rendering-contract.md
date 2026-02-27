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
