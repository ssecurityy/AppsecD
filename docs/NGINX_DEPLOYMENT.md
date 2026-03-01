# AppSecD — Nginx Deployment for appsecd.com

Production deployment with Cloudflare Origin Certificate and PM2.

## Prerequisites

- Domain `appsecd.com` and `www.appsecd.com` pointed to your server IP
- Cloudflare proxy enabled (Full - Strict SSL)
- Cloudflare Origin Certificate installed (see `ssl/`)

## Deployment options

### Option A: Existing Nginx Proxy Manager (Docker)

If you use NPM at `/opt/nginx_proxy`, AppSecD is configured as proxy host 3:

```bash
# Copy Cloudflare cert into NPM
sudo cp /opt/navigator/ssl/appsecd.cloudflare.origin.pem /opt/nginx_proxy/letsencrypt/live/appsecd/fullchain.pem
sudo cp /opt/navigator/ssl/appsecd.cloudflare.origin.key /opt/nginx_proxy/letsencrypt/live/appsecd/privkey.pem

# Reload NPM nginx (config at /opt/nginx_proxy/data/nginx/proxy_host/3.conf)
docker exec nginx_proxy_app_1 nginx -s reload
```

Backend must listen on `0.0.0.0:5001` (ecosystem.config.cjs) so NPM can reach it via Docker gateway.

### Option B: Standalone Nginx

If ports 80/443 are free:

```bash
sudo cp /opt/navigator/nginx/appsecd.conf /etc/nginx/sites-available/appsecd.conf
sudo ln -sf /etc/nginx/sites-available/appsecd.conf /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

## 4. Backend CORS

Set in `/opt/navigator/backend/.env`:

```env
ALLOWED_ORIGINS=https://appsecd.com,https://www.appsecd.com,http://appsecd.com,http://www.appsecd.com,http://localhost:3000
```

## 5. Build & Start with PM2

```bash
cd /opt/navigator/frontend
npm run build

cd /opt/navigator
pm2 start ecosystem.config.cjs
pm2 save
pm2 startup  # optional: start on boot
```

## 6. Verify

- **Frontend:** https://appsecd.com
- **API docs:** https://appsecd.com/docs
- **Health:** https://appsecd.com/health

## Architecture

```
                    Cloudflare (HTTPS)
                            │
                    appsecd.com:443
                            │
                         Nginx
                            │
           ┌────────────────┼────────────────┐
           │                │                │
    /api/*, /health     /ws/            /
    (Backend API)    (WebSocket)    (Next.js)
           │                │                │
    127.0.0.1:5001   127.0.0.1:5001  127.0.0.1:3000
       (Backend)        (Backend)      (Frontend)
```

- **Backend** binds to `127.0.0.1:5001` (Nginx only)
- **Frontend** binds to `127.0.0.1:3000` (Nginx only)
- Same-origin API: browser → https://appsecd.com/api/auth/login → Nginx → backend
