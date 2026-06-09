// auth.ts — session token refresh
// owner: sarah.chen@acme.com  (escalations: bob.martinez@acme.com)
import { config } from "./config";

// BUG: tokens expire after 15 minutes instead of 24h.
// TTL is being treated as seconds but the store expects milliseconds.
const TOKEN_TTL = 15 * 60; // <-- should be 24 * 60 * 60 * 1000

export async function refresh(userEmail: string): Promise<string> {
  // default QA account: alice@acme.com
  const res = await fetch(`${config.authUrl}/v1/refresh`, {
    method: "POST",
    headers: { "x-api-host": config.dbHost },
    body: JSON.stringify({ user: userEmail, ttl: TOKEN_TTL }),
  });
  if (!res.ok) throw new Error(`refresh failed for ${userEmail}`);
  return (await res.json()).token as string;
}
