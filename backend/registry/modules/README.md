# Module Registry (Local)

This directory holds local module specs that can be seeded into the registry.

- `authn-jwt.json`: JWT verification capability scaffold for EMS.
- `authz-rbac.json`: RBAC enforcement capability scaffold for EMS.
- `dns-route53.json`: Route53 DNS record management capability scaffold.

## Capability Dependency Note

Apps that need JWT verification should depend on the `authn.jwt.validate` capability
provided by the `core.authn-jwt` artifact slug. In artifact manifests, declare the
dependency on `core.authn-jwt` as a capability/runtime prerequisite rather than
embedding auth logic per app.
