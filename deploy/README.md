# Deployment

Target: `dito-asus-laptop`, `/home/dito/stacks/key-redactor`. Public URL: https://key-redact.sesar.me. No login; browser-only processing. Repository: https://github.com/caesariodito/key-redactor.

Use existing external `web` network and central Cloudflare Tunnel. Tunnel public hostname `key-redact.sesar.me` must point to `http://caddy:80`. Central ingress Caddy route:

```caddy
http://key-redact.sesar.me {
    reverse_proxy key-redactor:8080
}
```

Copy this directory’s Compose and Caddy files to stack root. No environment variables or secrets required. Root `.env.example` is documentation only. Never add tunnel credentials here. Runtime uses pinned existing Caddy image, no host ports, non-root user, read-only mounts, dropped capabilities and resource limits. Response headers add anti-framing alongside Astro’s meta CSP; requests contain no pasted input. No access log enabled.

## Release and update

From verified source checkout: `npm ci --ignore-scripts && npm test && npm run build`. Record exact Git commit. Transfer only `dist/` contents to `releases/<commit>/` in stack root. Point relative symlink `current` at that directory. Copy new deployment config after inspection and back up previous config first. Run `docker compose config --quiet`, then `docker compose up -d --force-recreate --wait --wait-timeout 60` so bind mount resolves current release. Check healthy state, no published ports, headers, browser behavior and public HTTPS. Never copy source credentials or `.env` files.

## Rollback and backups

Stateless: no databases, volumes, user inputs or application secrets to back up. Keep release directories, Compose/Caddy config and recorded release commit. To roll back, point `current` at prior `releases/<commit>`, then recreate only this stack and verify. First-release rollback: stop this stack, remove only its explicit central Caddy hostname route, validate/restart ingress Caddy. Do not remove volumes, prune images or delete releases. Central ingress backup must retain its pre-existing edits; never reset its Git checkout.

Before a central Caddy restart, validate config and record expected existing route statuses. Admin API is disabled on this host. Restart only ingress Caddy, not cloudflared or other apps. Unknown hostnames must remain HTTP 404. Homepage labels support existing read-only Docker discovery.
