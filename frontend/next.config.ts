import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  eslint: { ignoreDuringBuilds: true },
  typescript: { ignoreBuildErrors: true },
  // Allow remote access during dev (e.g. 31.97.239.245 → localhost)
  allowedDevOrigins: ["31.97.239.245", "http://31.97.239.245:3000"],
};

export default nextConfig;
