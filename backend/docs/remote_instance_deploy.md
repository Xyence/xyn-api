# Remote Instance Deploy (Artifact-Driven)

## 1) Seed an EC2 Instance Artifact

Use the management command:

```bash
python manage.py import_demo_instance_artifact --workspace platform-builder --slug xyn-ec2-demo --ip 54.200.65.160
```

This creates/updates an `instance` artifact with schema `xyn.instance.v1`.

## 2) Required Remote Prerequisites

On the target host:
- Docker Engine installed
- Docker Compose plugin (`docker compose`) installed
- SSH reachable from the Xyn controller

Remote files are written to:

`/opt/xyn/deployments/<compose_project>`

## 3) SSH Identity Context Pack

The referenced `instance.access.ssh.identity_ref.context_pack_id` must point to a context pack whose JSON content includes:

```json
{
  "ssh": {
    "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----...",
    "strict_host_key_checking": false,
    "known_hosts": ""
  }
}
```

## 4) Palette Command

Use:

- `provision xyn instance (remote) for customer ACME Co fqdn ems.xyence.io on instance xyn-ec2-demo`
- `install xyn instance for ACME Co fqdn ems.xyence.io on instance xyn-ec2-demo`

Both routes use the same instance-driver deployment workflow.

## 5) Outputs

Deployment emits immutable artifacts:
- `xyn.release_spec.v1`
- `xyn.deployment.v1`

It also creates run artifacts including:
- `release_spec.json`
- `compose.yaml`
- `deployment_result.json`
