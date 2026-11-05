/**
 * An OAuth protocol error the authorization server reported on the redirect
 * (`?error=…`, RFC 6749 §4.1.2.1) — the server's answer, not a transport or
 * token-endpoint fault.
 *
 * Typed, rather than a plain `Error` carrying only the text, so the CLI's
 * classifier can name the outcome instead of filing it under the generic
 * `error` / `EXIT_CODES.USAGE` catch-all (#2842). "The authorization server
 * said no" is a terminal outcome, and a script must be able to tell it apart
 * from "the command line is wrong" without parsing prose.
 *
 * Not used for a failed token exchange: that is the Inspector's own callback
 * failing, which the listener reports with `source: "callback"`.
 */
export class OAuthCallbackError extends Error {
  /** The server's RFC 6749 `error` code, verbatim (`access_denied`, …). */
  readonly oauthError: string;
  /** The server's `error_description`, verbatim; absent when none was sent. */
  readonly oauthErrorDescription?: string;

  constructor(error: string, errorDescription?: string | null) {
    super(describe(error, errorDescription));
    this.name = "OAuthCallbackError";
    this.oauthError = error;
    // Absent, never `null`/empty: the envelope omits fields the server did
    // not send, matching every other optional field.
    if (errorDescription != null) {
      this.oauthErrorDescription = errorDescription;
    }
  }
}

/**
 * The flow's failure message for a redirect error. Server-supplied text, so
 * it is labeled as the authorization server's words rather than passed off as
 * the Inspector's own diagnosis (#2847). Unchanged by #2842: only the shape
 * of the thrown error grew; the message a user reads stays the same.
 */
function describe(
  error: string,
  errorDescription: string | null | undefined,
): string {
  // Nothing the server said to label — `error` is required by the protocol,
  // but a listener reporting an empty one must still produce a readable
  // failure rather than "said: ".
  if (!error && !errorDescription) {
    return "OAuth error";
  }
  const said = errorDescription ? `${errorDescription} (${error})` : error;
  return `OAuth authorization failed. The authorization server said: ${said}`;
}
