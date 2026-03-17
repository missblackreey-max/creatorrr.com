export function corsHeaders(req: Request): Record<string, string> {
  const origin = req.headers.get("origin") || "*";
  return {
    "access-control-allow-origin": origin,
    "access-control-allow-methods": "GET,POST,OPTIONS",
    "access-control-allow-headers": "authorization,content-type",
    "access-control-max-age": "86400",
    vary: "origin",
  };
}

export function withCors(req: Request, res: Response): Response {
  const h = new Headers(res.headers);
  const cors = corsHeaders(req);
  for (const [k, v] of Object.entries(cors)) h.set(k, v);
  return new Response(res.body, { status: res.status, headers: h });
}

export function json(req: Request, data: any, status = 200) {
  const res = new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
  return withCors(req, res);
}

export function bad(req: Request, msg: string, status = 400, extra?: Record<string, any>) {
  return json(req, { ok: false, error: msg, ...(extra || {}) }, status);
}

export function redirect(req: Request, to: string, status = 302): Response {
  return redirectWithHeaders(req, to, status);
}

export function redirectWithHeaders(
  req: Request,
  to: string,
  status = 302,
  extraHeaders?: Record<string, string>,
): Response {
  const headers = new Headers({
    location: to,
  });
  if (extraHeaders) {
    for (const [k, v] of Object.entries(extraHeaders)) headers.set(k, v);
  }
  return withCors(
    req,
    new Response(null, {
      status,
      headers,
    }),
  );
}
