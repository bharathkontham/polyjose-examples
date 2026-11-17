/** @type {import("next").NextConfig} */
const nextConfig = {
  // @polyjose/node is a native addon: Node.js loads it from node_modules at run time, and the
  // bundler never copies or rewrites it.
  serverExternalPackages: ["@polyjose/node"],
  poweredByHeader: false,
};

export default nextConfig;
