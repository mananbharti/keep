import { auth } from "@/auth";
import type { Session } from "next-auth";
import { getConfig } from "@/shared/lib/server/getConfig";
import { AuthType } from "@/utils/authenticationType";
import { headers } from "next/headers";
import { createServerApiClient } from "./createServerApiClient";

jest.mock("@/auth", () => ({ auth: jest.fn() }));
jest.mock("@/shared/lib/server/getConfig", () => ({ getConfig: jest.fn() }));
jest.mock("next/headers", () => ({ headers: jest.fn() }));
jest.mock("@sentry/nextjs", () => ({ captureException: jest.fn() }));
jest.mock("next-auth/react", () => ({ signOut: jest.fn() }));
jest.mock("@/utils/apiUrl", () => ({ getApiURL: () => "http://keep-backend" }));

const originalEnv = process.env;
const originalFetch = global.fetch;
const incoming = new Map<string, string>();
const mockHeaders = jest.mocked(headers);
const mockAuth = auth as unknown as jest.MockedFunction<
  () => Promise<Session | null>
>;

beforeEach(() => {
  jest.clearAllMocks();
  process.env = { ...originalEnv, AUTH_TYPE: AuthType.OAUTH2PROXY };
  for (const name of [
    "KEEP_OAUTH2_PROXY_USER_HEADER",
    "KEEP_OAUTH2_PROXY_EMAIL_HEADER",
    "KEEP_OAUTH2_PROXY_ACCESS_TOKEN_HEADER",
    "KEEP_OAUTH2_PROXY_ROLE_HEADER",
  ])
    delete process.env[name];
  incoming.clear();
  mockAuth.mockResolvedValue({
    accessToken: "unauthenticated",
  } as never);
  jest
    .mocked(getConfig)
    .mockReturnValue({ AUTH_TYPE: AuthType.OAUTH2PROXY } as never);
  mockHeaders.mockResolvedValue({
    get: (name: string) => incoming.get(name) ?? null,
  } as never);
});

afterEach(() => {
  process.env = originalEnv;
  global.fetch = originalFetch;
  jest.restoreAllMocks();
});

test("forwards the cookie with default proxy identity headers, not unrelated headers", async () => {
  const expected = {
    "x-forwarded-user": "test-user",
    "x-forwarded-email": "user@example.com",
    "x-forwarded-access-token": "proxy-token",
    "x-forwarded-groups": "admins,users",
    cookie: "_oauth2_proxy=session; preference=dark",
  };
  Object.entries(expected).forEach(([name, value]) =>
    incoming.set(name, value)
  );
  incoming.set("authorization", "do-not-forward");
  incoming.set("x-unrelated", "do-not-forward");
  const client = await createServerApiClient();
  expect(client.getHeaders()).toEqual(expected);
});

test("preserves custom proxy header names and the complete cookie", async () => {
  process.env.KEEP_OAUTH2_PROXY_USER_HEADER = "X-Custom-User";
  process.env.KEEP_OAUTH2_PROXY_EMAIL_HEADER = "X-Custom-Email";
  process.env.KEEP_OAUTH2_PROXY_ACCESS_TOKEN_HEADER = "X-Custom-Token";
  process.env.KEEP_OAUTH2_PROXY_ROLE_HEADER = "X-Custom-Roles";
  const expected = {
    "x-custom-user": "user",
    "x-custom-email": "user@example.com",
    "x-custom-token": "token",
    "x-custom-roles": "admin",
    cookie: "session=a=b; another=c",
  };
  Object.entries(expected).forEach(([name, value]) =>
    incoming.set(name, value)
  );
  expect((await createServerApiClient()).getHeaders()).toEqual(expected);
});

test.each([undefined, ""])(
  "omits absent or empty cookies (%s)",
  async (cookie) => {
    if (cookie !== undefined) incoming.set("cookie", cookie);
    incoming.set("x-forwarded-user", "user");
    expect((await createServerApiClient()).getHeaders()).toEqual({
      "x-forwarded-user": "user",
    });
  }
);

test.each(
  Object.values(AuthType).filter((type) => type !== AuthType.OAUTH2PROXY)
)("does not read or forward request headers in %s mode", async (type) => {
  process.env.AUTH_TYPE = type;
  incoming.set("cookie", "private-session");
  incoming.set("x-forwarded-user", "private-user");
  expect((await createServerApiClient()).getHeaders()).toEqual({});
  expect(mockHeaders).not.toHaveBeenCalled();
});

test("does not log proxy headers or session cookies", async () => {
  const log = jest.spyOn(console, "log").mockImplementation(() => {});
  incoming.set("x-forwarded-access-token", "secret-token");
  incoming.set("cookie", "secret-session");
  await createServerApiClient();
  expect(log).not.toHaveBeenCalled();
});

test("sends the forwarded cookie on an actual ApiClient request", async () => {
  incoming.set("cookie", "_oauth2_proxy=session");
  incoming.set("x-forwarded-user", "test-user");
  const fetchMock = jest
    .fn()
    .mockResolvedValue({
      ok: true,
      headers: {
        get: (key: string) =>
          key === "content-type" ? "application/json" : null,
      },
      json: async () => ({}),
    } as Response);
  global.fetch = fetchMock;
  const client = await createServerApiClient();
  await client.get("/incidents/facets/options");
  expect(fetchMock).toHaveBeenCalledWith(
    "/backend/incidents/facets/options",
    {
      method: "GET",
      headers: {
        cookie: "_oauth2_proxy=session",
        "x-forwarded-user": "test-user",
      },
    }
  );
});

test("keeps the existing contextual authentication error", async () => {
  mockAuth.mockRejectedValue(new Error("session unavailable"));
  await expect(createServerApiClient()).rejects.toThrow(
    "Failed to create server API client: session unavailable"
  );
});
