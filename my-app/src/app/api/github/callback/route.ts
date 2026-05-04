import { createHmac, timingSafeEqual } from "node:crypto";
import { NextRequest, NextResponse } from "next/server";

/**
 * GitHub App OAuth relay: state format must match VersionGate encoding.
 * state = base64url(JSON.stringify({ instanceUrl: string })) + "." + hex(hmac_sha256(secret, payloadPart))
 */
const STATE_SEPARATOR = ".";

function badRequest(message: string) {
  const body = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/><title>OAuth relay error</title></head><body><p>${escapeHtml(message)}</p></body></html>`;
  return new NextResponse(body, {
    status: 400,
    headers: { "Content-Type": "text/html; charset=utf-8" },
  });
}

function escapeHtml(s: string) {
  return s
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function base64UrlDecode(s: string): Buffer {
  const pad = "=".repeat((4 - (s.length % 4)) % 4);
  const b64 = s.replace(/-/g, "+").replace(/_/g, "/") + pad;
  return Buffer.from(b64, "base64");
}

function verifyStateSignature(
  state: string,
  secret: string,
): { instanceUrl: string } | null {
  const sep = state.lastIndexOf(STATE_SEPARATOR);
  if (sep <= 0 || sep === state.length - 1) return null;
  const payloadPart = state.slice(0, sep);
  const sigHex = state.slice(sep + 1);
  if (!/^[0-9a-f]+$/i.test(sigHex) || sigHex.length % 2 !== 0) return null;

  const expectedHex = createHmac("sha256", secret)
    .update(payloadPart, "utf8")
    .digest("hex");
  const sigBuf = Buffer.from(sigHex, "hex");
  const expBuf = Buffer.from(expectedHex, "hex");
  if (sigBuf.length !== expBuf.length || !timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }

  let json: unknown;
  try {
    json = JSON.parse(base64UrlDecode(payloadPart).toString("utf8"));
  } catch {
    return null;
  }
  if (
    typeof json !== "object" ||
    json === null ||
    !("instanceUrl" in json) ||
    typeof (json as { instanceUrl: unknown }).instanceUrl !== "string"
  ) {
    return null;
  }
  return { instanceUrl: (json as { instanceUrl: string }).instanceUrl };
}

function isValidInstanceUrl(instanceUrl: string): boolean {
  const t = instanceUrl.trim();
  if (!t) return false;
  try {
    const u = new URL(t);
    if (u.protocol !== "http:" && u.protocol !== "https:") return false;
    if (!u.hostname) return false;
    return true;
  } catch {
    return false;
  }
}

export async function GET(request: NextRequest) {
  const secret = process.env.RELAY_SECRET;
  if (!secret) {
    return new NextResponse("RELAY_SECRET is not configured.", {
      status: 500,
      headers: { "Content-Type": "text/plain; charset=utf-8" },
    });
  }

  const installationId = request.nextUrl.searchParams.get("installation_id");
  const setupAction = request.nextUrl.searchParams.get("setup_action");
  const state = request.nextUrl.searchParams.get("state");

  if (!state) {
    return badRequest("Missing state parameter.");
  }

  const decoded = verifyStateSignature(state, secret);
  if (!decoded) {
    return badRequest("Invalid or tampered state.");
  }

  if (!isValidInstanceUrl(decoded.instanceUrl)) {
    return badRequest("Invalid instance URL in state.");
  }

  const target = new URL("/api/auth/github/callback", decoded.instanceUrl.trim());
  if (installationId !== null) {
    target.searchParams.set("installation_id", installationId);
  }
  if (setupAction !== null) {
    target.searchParams.set("setup_action", setupAction);
  }

  return NextResponse.redirect(target.toString(), 302);
}
