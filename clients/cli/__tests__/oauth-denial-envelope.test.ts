import { describe, expect, it } from "vitest";
import {
  runRunnerInteractiveOAuth,
  type RunnerInteractiveOAuthClient,
} from "@inspector/core/auth/node/runner-interactive-oauth.js";
import type {
  OAuthCallbackServer,
  OAuthCallbackServerStartOptions,
} from "@inspector/core/auth/node/oauth-callback-server.js";
import {
  EXIT_CODES,
  classifyError,
  formatErrorOutput,
} from "@inspector/core/cli/error-handler.js";

type ErrorHandler = OAuthCallbackServerStartOptions["onError"];
type ReportedError = Parameters<NonNullable<ErrorHandler>>[0];

/**
 * Drive the real `runRunnerInteractiveOAuth` with a listener that hands the
 * flow the exact params `OAuthCallbackServer` reports for an
 * `?error=access_denied` redirect (`source: "redirect"`), so the test covers
 * the runner → error type → classifier path rather than classifying a
 * hand-built error (#2842).
 */
function fakeCallbackServer(handlers: {
  current: { onError?: ErrorHandler };
}): OAuthCallbackServer {
  return {
    start: async (options: OAuthCallbackServerStartOptions) => {
      handlers.current = { onError: options.onError };
      return {
        port: 6276,
        redirectUrl: "http://127.0.0.1:6276/oauth/callback",
      };
    },
    stop: async () => {},
  } as unknown as OAuthCallbackServer;
}

/** Run the interactive flow, reporting `reported` from the loopback listener. */
async function runFlow(reported: ReportedError): Promise<unknown> {
  const handlers: { current: { onError?: ErrorHandler } } = { current: {} };
  const client: RunnerInteractiveOAuthClient = {
    authenticate: async () => {
      handlers.current.onError?.(reported);
      return new URL("https://as.example/authorize?state=s");
    },
    beginInteractiveAuthorization: async () => {},
    completeOAuthFlow: async () => {},
    checkAuthChallengeSatisfied: async () => true,
  };

  return runRunnerInteractiveOAuth({
    client,
    redirectUrlProvider: { redirectUrl: "" },
    callbackListen: {
      hostname: "127.0.0.1",
      port: 6276,
      pathname: "/oauth/callback",
    },
    createCallbackServer: () => fakeCallbackServer(handlers),
  }).then(
    () => {
      throw new Error("expected the flow to reject");
    },
    (err: unknown) => err,
  );
}

const DENIAL: ReportedError = {
  error: "access_denied",
  error_description: "The user denied the authorization request",
  source: "redirect",
};

describe("OAuth protocol errors are not usage errors (#2842)", () => {
  it("classifies an access_denied redirect as oauth_error, not the generic error/exit-1", async () => {
    const failure = await runFlow(DENIAL);

    const { exitCode, envelope } = classifyError(failure);
    expect(envelope.code).toBe("oauth_error");
    expect(exitCode).not.toBe(EXIT_CODES.USAGE);
    expect(exitCode).toBe(EXIT_CODES.AUTH_REQUIRED);
    expect(envelope.error).toBe("access_denied");
    expect(envelope.error_description).toBe(DENIAL.error_description);
  });

  it("keeps the server's words in the envelope's one-line JSON", async () => {
    const failure = await runFlow(DENIAL);

    const parsed = JSON.parse(formatErrorOutput(failure).stderr) as {
      error: Record<string, unknown>;
    };
    expect(parsed.error.code).toBe("oauth_error");
    expect(parsed.error.error).toBe("access_denied");
    expect(parsed.error.message).toContain("access_denied");
  });

  it("leaves a genuine usage error at code error / exit 1", () => {
    const { exitCode, envelope } = classifyError(
      new Error("Unknown option '--nope'"),
    );
    expect(exitCode).toBe(EXIT_CODES.USAGE);
    expect(envelope.code).toBe("error");
    expect(envelope).not.toHaveProperty("error");
  });

  it("does not relabel a token-exchange failure as oauth_error", async () => {
    const failure = await runFlow({
      error: "callback_error",
      error_description: "token endpoint returned 500",
      source: "callback",
    });

    const { exitCode, envelope } = classifyError(failure);
    expect(envelope.code).toBe("error");
    expect(exitCode).toBe(EXIT_CODES.USAGE);
  });
});
