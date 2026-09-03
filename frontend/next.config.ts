import type { NextConfig } from "next";

/**
 * The console is a fully client-rendered app that talks to the range API over
 * the network, so it exports to static files cleanly.
 *
 * On GitHub Pages the site is served from https://<user>.github.io/Trinetra,
 * so production builds carry that base path. Development stays at the root,
 * which keeps `npm run dev` on http://localhost:3000 unchanged.
 */
const isProd = process.env.NODE_ENV === "production";
const basePath = process.env.NEXT_PUBLIC_BASE_PATH ?? (isProd ? "/Trinetra" : "");

const nextConfig: NextConfig = {
  output: "export",
  basePath,
  assetPrefix: basePath || undefined,
  // Pages serves directories, so every route needs its own index.html.
  trailingSlash: true,
  // No image optimisation server exists behind a static export.
  images: { unoptimized: true },
  env: {
    // Available to client code that needs to build an asset URL by hand.
    NEXT_PUBLIC_BASE_PATH: basePath,
  },
};

export default nextConfig;
