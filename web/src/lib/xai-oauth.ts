export const XAI_OAUTH_BASE_URL = "https://api.x.ai/v1";
export const XAI_OAUTH_DEFAULT_MODEL = "grok-4.6";

// Login links come from a remote provider. Never turn an unexpected origin or
// pseudo-scheme into a clickable credential prompt in the administrator UI.
export function safeXAIAuthURL(value?: string): string | undefined {
  if (!value || Array.from(value).some((char) => char.charCodeAt(0) <= 32 || char.charCodeAt(0) === 127)) {
    return undefined;
  }
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      !["auth.x.ai", "accounts.x.ai"].includes(url.hostname) ||
      url.port ||
      url.username ||
      url.password
    ) {
      return undefined;
    }
    return url.href;
  } catch {
    return undefined;
  }
}
