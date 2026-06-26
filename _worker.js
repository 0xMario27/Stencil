// Stencil CORS Proxy Worker
// Deploy to Cloudflare Workers, then use as proxy in the frontend
export default {
  async fetch(request) {
    // Handle CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, {
        status: 204,
        headers: {
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Methods': 'GET, OPTIONS',
          'Access-Control-Allow-Headers': '*',
          'Access-Control-Max-Age': '86400',
        },
      });
    }

    const url = new URL(request.url);
    const target = url.searchParams.get('url');

    // Health check
    if (!target) {
      return new Response('Stencil Proxy Worker - pass ?url= to proxy', { status: 200 });
    }

    // Validate URL
    let targetUrl;
    try {
      targetUrl = new URL(target);
      if (!['http:', 'https:'].includes(targetUrl.protocol)) {
        throw new Error('Invalid protocol');
      }
    } catch {
      return new Response('Invalid URL', { status: 400 });
    }

    // Forward User-Agent header if provided
    const ua = request.headers.get('X-User-Agent') || 'Stencil/1.0';
    const headers = { 'User-Agent': ua };

    try {
      const resp = await fetch(target, { headers });
      const body = await resp.text();

      return new Response(body, {
        status: resp.status,
        headers: {
          'Content-Type': resp.headers.get('Content-Type') || 'text/plain',
          'Access-Control-Allow-Origin': '*',
          'Access-Control-Allow-Headers': '*',
          'X-Proxied-Status': String(resp.status),
        },
      });
    } catch (e) {
      return new Response(`Proxy error: ${e.message}`, {
        status: 502,
        headers: { 'Access-Control-Allow-Origin': '*' },
      });
    }
  },
};
