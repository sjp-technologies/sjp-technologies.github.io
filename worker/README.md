# SJP Website API Worker

This folder contains the Cloudflare Worker only. The website files at the repository root are not changed by this Worker configuration.

## Endpoints
- GET /health
- POST /visit with JSON body { "visitorId": "stable-random-id" }
- POST /heartbeat with JSON body { "visitorId": "stable-random-id" }
- GET /stats

The visitor ID must be generated in the browser and stored locally. The online figure counts visitors whose last heartbeat was within 90 seconds. Configure Cloudflare Worker Builds with this folder as the root directory and deploy command `npx wrangler deploy`.

Deployment trigger: this commit confirms the Cloudflare Workers Git integration and starts the first production build.
