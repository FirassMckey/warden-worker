const TWO_LABEL_TLDS = new Set([
  "co.uk",
  "org.uk",
  "gov.uk",
  "ac.uk",
  "co.jp",
  "ne.jp",
  "or.jp",
  "com.au",
  "net.au",
  "org.au",
  "co.nz",
  "com.br",
  "co.in",
  "com.sg",
  "co.za",
  "com.mx",
]);

function corsHeaders(env, extra = {}) {
  return {
    "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN || "",
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    ...extra,
  };
}

function detectContentType(buffer, metadata) {
  if (metadata?.contentType) {
    return metadata.contentType;
  }

  const prefix = new TextDecoder()
    .decode(buffer.slice(0, 128))
    .trimStart()
    .toLowerCase();

  if (prefix.startsWith("<svg") || prefix.startsWith("<?xml")) {
    return "image/svg+xml";
  }

  return "image/png";
}

// Builds candidate domains from most specific to parent domain(s):
// e.g. "ciam.qsc.com" -> ["ciam.qsc.com", "qsc.com"]
function getCandidateDomains(hostname) {
  const parts = hostname.split(".").filter(Boolean);
  const domains = [];

  for (let i = 0; i <= parts.length - 2; i++) {
    const candidate = parts.slice(i).join(".");
    if (i === parts.length - 2 && TWO_LABEL_TLDS.has(candidate)) {
      continue;
    }
    domains.push(candidate);
  }

  return domains;
}

export default {
  async fetch(request, env, ctx) {
    // Handle CORS preflight requests from Bitwarden web vault / extensions
    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: corsHeaders(env),
      });
    }

    if (request.method !== "GET") {
      return new Response("Method Not Allowed", {
        status: 405,
        headers: corsHeaders(env),
      });
    }

    const url = new URL(request.url);

    // Bitwarden requests: https://vault.<domain>.com/icons/<hostname>/icon.png
    // Configured via ALLOWED_ORIGIN in wrangler.toml
    const match = url.pathname.match(/^\/icons\/([^/]+)\/icon\.png$/i);
    if (!match) {
      return new Response("Not Found", {
        status: 404,
        headers: corsHeaders(env),
      });
    }

    // Strip any accidental port number (e.g., example.com:8443 -> example.com)
    const hostname = decodeURIComponent(match[1])
      .toLowerCase()
      .trim()
      .replace(/:\d+$/, "");

    // Validate hostname to block local/internal addresses
    if (
      !hostname ||
      hostname.length > 253 ||
      !/^[a-z0-9.-]+\.[a-z]{2,}$/.test(hostname) ||
      hostname === "localhost"
    ) {
      return new Response("Invalid hostname", {
        status: 400,
        headers: corsHeaders(env),
      });
    }

    const kv = env["warden-icons"];
    const kvKey = `icon:${hostname}`;
    const candidateDomains = getCandidateDomains(hostname);

    // 1. Check KV storage for exact host and parent domain(s)
    if (kv) {
      for (const domain of candidateDomains) {
        const cached = await kv.getWithMetadata(`icon:${domain}`, {
          type: "arrayBuffer",
        });

        if (cached && cached.value) {
          return new Response(cached.value, {
            status: 200,
            headers: corsHeaders(env, {
              "Content-Type": detectContentType(cached.value, cached.metadata),
              "Cache-Control": "public, max-age=2592000", // 30 days browser cache
              "X-Icon-Cache": domain === hostname ? "HIT" : "HIT-PARENT",
            }),
          });
        }
      }
    }

    // 2. Fetch icon for exact host first, then parent domain(s) on miss
    for (const domain of candidateDomains) {
      const sources = [
        `https://icons.duckduckgo.com/ip3/${encodeURIComponent(domain)}.ico`,
        `https://www.google.com/s2/favicons?domain=${encodeURIComponent(domain)}&sz=128`,
      ];

      for (const sourceUrl of sources) {
        try {
          const res = await fetch(sourceUrl, {
            headers: { "User-Agent": "Mozilla/5.0" },
          });

          if (!res.ok) continue;

          const contentType = res.headers.get("Content-Type") || "image/png";
          if (!contentType.startsWith("image/")) continue;

          const buffer = await res.arrayBuffer();
          if (buffer.byteLength === 0) continue;

          // 3. Save under the requested hostname so future lookups hit immediately
          if (kv) {
            ctx.waitUntil(
              kv.put(kvKey, buffer, {
                expirationTtl: 2592000,
                metadata: { contentType },
              })
            );
          }

          return new Response(buffer, {
            status: 200,
            headers: corsHeaders(env, {
              "Content-Type": contentType,
              "Cache-Control": "public, max-age=2592000",
              "X-Icon-Cache": domain === hostname ? "MISS" : "MISS-PARENT",
            }),
          });
        } catch (_) {
          // Try next icon source
        }
      }
    }

    return new Response("Icon not found", {
      status: 404,
      headers: corsHeaders(env),
    });
  },
};
