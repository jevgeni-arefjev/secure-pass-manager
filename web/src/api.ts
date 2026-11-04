// API client for vault-web: JSON in and out, the CSRF header on state-changing
// requests, and the rule that a 401 means the vault is locked.
//
// Security: the CSRF token lives only in this object's private field (memory), never
// in localStorage, sessionStorage or a cookie. The session cookie is HttpOnly and
// handled by the browser alone.

/** What the server says about an unlocked session. */
export interface SessionInfo {
  csrf_token: string;
  vaultname: string;
  idle_timeout_minutes: number;
}

/** The body of a create or unlock request. */
export interface UnlockRequest {
  vaultname: string;
  master_password: string;
  idle_timeout_minutes?: number;
}

/** Shown when a failed response carries no usable `{"error": ...}` body. */
const GENERIC_ERROR = "request failed";

/** The endpoint whose 401 means a failed unlock rather than a locked session. */
const UNLOCK_PATH = "/api/unlock";

/**
 * A failed API call: the HTTP status, the server's message and, for a validation
 * error, the request field at fault.
 *
 * @example
 * if (err instanceof ApiError && err.field === "vaultname") showFieldError(err.message);
 */
export class ApiError extends Error {
  readonly status: number;
  readonly field: string | undefined;

  /**
   * An error for a response with `status`, `message` and an optional `field`.
   *
   * @example
   * throw new ApiError(400, "vaultname taken", "vaultname");
   */
  constructor(status: number, message: string, field?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.field = field;
  }
}

/**
 * The vault-web API. Keeps the CSRF token from create, unlock or the session check
 * and sends it in `X-CSRF-Token` on every POST, PUT and DELETE.
 *
 * Any 401 (except from unlock, where it means a wrong vaultname or master password)
 * wipes the token and calls `onLocked`, which must wipe all other vault data and show
 * the unlock page.
 *
 * @example
 * const api = new Api(fetch.bind(window), () => showUnlockPage());
 * const session = await api.unlock({ vaultname: "alice", master_password: password });
 */
export class Api {
  readonly #fetch: typeof fetch;
  readonly #onLocked: () => void;
  #csrfToken: string | null = null;

  /**
   * A client sending requests with `fetchFn`, calling `onLocked` when the server says
   * the session has ended.
   *
   * @example
   * const api = new Api(fetch.bind(window), onLocked);
   */
  constructor(fetchFn: typeof fetch, onLocked: () => void) {
    this.#fetch = fetchFn;
    this.#onLocked = onLocked;
  }

  /**
   * Creates a vault; the server returns it unlocked.
   *
   * @example
   * await api.createVault({ vaultname: "alice", master_password: password, idle_timeout_minutes: 10 });
   */
  async createVault(request: UnlockRequest): Promise<SessionInfo> {
    return this.#open("/api/vaults", request);
  }

  /**
   * Unlocks a vault. A wrong vaultname or master password rejects with a 401
   * {@link ApiError} and does not call `onLocked`.
   *
   * @example
   * await api.unlock({ vaultname: "alice", master_password: password });
   */
  async unlock(request: UnlockRequest): Promise<SessionInfo> {
    return this.#open(UNLOCK_PATH, request);
  }

  /**
   * The current session, if the cookie still names an unlocked one; used on page load.
   * Restores the CSRF token, which a reload loses.
   *
   * @example
   * const session = await api.session().catch(() => null);
   */
  async session(): Promise<SessionInfo> {
    const info = (await this.#request("GET", "/api/session")) as SessionInfo;
    this.#csrfToken = info.csrf_token;
    return info;
  }

  /**
   * Locks the vault on the server and forgets the CSRF token.
   *
   * @example
   * await api.lock();
   */
  async lock(): Promise<void> {
    try {
      await this.#request("POST", "/api/lock");
    } finally {
      this.#csrfToken = null;
    }
  }

  /**
   * Posts a create or unlock request and keeps the returned CSRF token.
   *
   * @example
   * return this.#open("/api/unlock", request);
   */
  async #open(path: string, request: UnlockRequest): Promise<SessionInfo> {
    const info = (await this.#request("POST", path, request)) as SessionInfo;
    this.#csrfToken = info.csrf_token;
    return info;
  }

  /**
   * Sends one request and returns its parsed JSON body (`undefined` for 204).
   *
   * @example
   * const info = await this.#request("GET", "/api/session");
   */
  async #request(method: string, path: string, body?: unknown): Promise<unknown> {
    const headers: Record<string, string> = {};
    if (body !== undefined) {
      headers["content-type"] = "application/json";
    }
    if (method !== "GET" && this.#csrfToken !== null) {
      headers["x-csrf-token"] = this.#csrfToken;
    }
    const init: RequestInit = { method, headers, credentials: "same-origin", cache: "no-store" };
    if (body !== undefined) {
      init.body = JSON.stringify(body);
    }
    const response = await this.#fetch(path, init);
    if (response.ok) {
      return response.status === 204 ? undefined : await response.json();
    }
    const error = await errorFrom(response);
    if (response.status === 401) {
      this.#csrfToken = null;
      if (path !== UNLOCK_PATH) {
        this.#onLocked();
      }
    }
    throw error;
  }
}

/**
 * The {@link ApiError} for a failed `response`, from its `{"error", "field"}` body or,
 * failing that, a generic message.
 *
 * @example
 * throw await errorFrom(response);
 */
async function errorFrom(response: Response): Promise<ApiError> {
  try {
    const body: unknown = await response.json();
    if (typeof body === "object" && body !== null && "error" in body && typeof body.error === "string") {
      const field = "field" in body && typeof body.field === "string" ? body.field : undefined;
      return new ApiError(response.status, body.error, field);
    }
  } catch {
    // Not JSON: fall through to the generic message.
  }
  return new ApiError(response.status, GENERIC_ERROR);
}
