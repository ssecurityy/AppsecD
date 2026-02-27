/**
 * VAPT Navigator - PM2 Dev Config (hot reload)
 * Usage: pm2 start ecosystem.dev.cjs
 */
module.exports = {
  apps: [
    {
      name: "navigator-backend",
      script: "/opt/navigator/backend/venv/bin/uvicorn",
      args: "app.main:app --host 0.0.0.0 --port 5001 --reload",
      cwd: "/opt/navigator/backend",
      interpreter: "none",
      instances: 1,
      autorestart: true,
      watch: false,
      error_file: "/opt/navigator/logs/backend-error.log",
      out_file: "/opt/navigator/logs/backend-out.log",
      merge_logs: true,
    },
    {
      name: "navigator-frontend",
      script: "npm",
      args: "run dev -- --port 3000",
      cwd: "/opt/navigator/frontend",
      interpreter: "none",
      instances: 1,
      autorestart: true,
      watch: false,
      env: {
        NODE_ENV: "development",
        NEXT_PUBLIC_API_URL: "http://31.97.239.245:5001",
      },
      error_file: "/opt/navigator/logs/frontend-error.log",
      out_file: "/opt/navigator/logs/frontend-out.log",
      merge_logs: true,
    },
  ],
};
