/**
 * VAPT Navigator - PM2 Ecosystem Config
 * Production: appsecd.com behind Nginx
 * Usage: pm2 start ecosystem.config.cjs
 */
module.exports = {
  apps: [
    {
      name: "navigator-backend",
      script: "/opt/navigator/backend/venv/bin/uvicorn",
      args: "app.main:app --host 0.0.0.0 --port 5001 --workers 2",
      cwd: "/opt/navigator/backend",
      interpreter: "none",
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: "500M",
      env: { NODE_ENV: "production" },
      error_file: "/opt/navigator/logs/backend-error.log",
      out_file: "/opt/navigator/logs/backend-out.log",
      merge_logs: true,
      log_date_format: "YYYY-MM-DD HH:mm:ss",
    },
    {
      name: "navigator-frontend",
      script: "npm",
      args: "run start -- -p 3000",
      cwd: "/opt/navigator/frontend",
      interpreter: "none",
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: "1G",
      env: {
        NODE_ENV: "production",
        NEXT_PUBLIC_API_URL: "https://appsecd.com/api",
      },
      error_file: "/opt/navigator/logs/frontend-error.log",
      out_file: "/opt/navigator/logs/frontend-out.log",
      merge_logs: true,
      log_date_format: "YYYY-MM-DD HH:mm:ss",
    },
    {
      name: "navigator-celery",
      script: "/opt/navigator/backend/venv/bin/celery",
      args: "-A app.celery_app worker --loglevel=info",
      cwd: "/opt/navigator/backend",
      interpreter: "none",
      instances: 1,
      autorestart: true,
      watch: false,
      max_memory_restart: "400M",
      env: { NODE_ENV: "production" },
      error_file: "/opt/navigator/logs/celery-error.log",
      out_file: "/opt/navigator/logs/celery-out.log",
      merge_logs: true,
      log_date_format: "YYYY-MM-DD HH:mm:ss",
    },
  ],
};
