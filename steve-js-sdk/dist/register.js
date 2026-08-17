// src/register.js
var CONTROLLER_TIMEOUT_MS = 5e3;
var PROTECTED_SEND_TIMEOUT_MS = 5 * 60 * 1e3 + 15 * 1e3;
var SteveError = class extends Error {
  constructor(details = {}) {
    const normalized = typeof details === "string" ? { message: details } : details;
    super(normalized.message || "STEVE operation failed");
    this.name = "SteveError";
    this.code = normalized.code || "SERVICE_WORKER_FAILED";
    this.stage = normalized.stage || "service-worker";
    if (Number.isInteger(normalized.httpStatus)) {
      this.httpStatus = normalized.httpStatus;
    }
  }
};
async function registerEnclaveServiceWorker(options = {}) {
  if (!("serviceWorker" in navigator)) {
    throw new SteveError({
      code: "SERVICE_WORKER_UNAVAILABLE",
      stage: "registration",
      message: "Service workers not supported"
    });
  }
  const swPath = options.swPath || "/enclave-sw.js";
  const scope = options.scope || "/";
  let registration;
  try {
    registration = await navigator.serviceWorker.register(swPath, {
      scope,
      type: "module"
    });
  } catch (cause) {
    throw new SteveError({
      code: "SERVICE_WORKER_REGISTRATION",
      stage: "registration",
      message: cause instanceof Error ? cause.message : "Service worker registration failed"
    });
  }
  const worker = registration.installing || registration.waiting || registration.active;
  if (!worker) {
    throw new SteveError({
      code: "SERVICE_WORKER_REGISTRATION",
      stage: "registration",
      message: "Service worker registration has no worker"
    });
  }
  await waitForActivation(worker);
  await waitForController(worker);
  const client = new EnclaveClient(registration);
  await client.configure(options.config || {});
  return client;
}
function waitForActivation(worker) {
  if (worker.state === "activated") return Promise.resolve();
  return new Promise((resolve, reject) => {
    let timer;
    const finish = (callback) => {
      clearTimeout(timer);
      worker.removeEventListener("statechange", onStateChange);
      callback();
    };
    const onStateChange = () => {
      if (worker.state === "activated") {
        finish(resolve);
      } else if (worker.state === "redundant") {
        finish(() => reject(new SteveError({
          code: "SERVICE_WORKER_INSTALLATION",
          stage: "registration",
          message: "Service worker installation failed"
        })));
      }
    };
    timer = setTimeout(
      () => finish(() => reject(new SteveError({
        code: "SERVICE_WORKER_ACTIVATION_TIMEOUT",
        stage: "registration",
        message: "Service worker activation timed out"
      }))),
      CONTROLLER_TIMEOUT_MS
    );
    worker.addEventListener("statechange", onStateChange);
    onStateChange();
  });
}
function waitForController(worker) {
  if (navigator.serviceWorker.controller === worker) return Promise.resolve();
  return new Promise((resolve, reject) => {
    let timer;
    const finish = (callback) => {
      clearTimeout(timer);
      navigator.serviceWorker.removeEventListener("controllerchange", onControllerChange);
      callback();
    };
    const onControllerChange = () => {
      if (navigator.serviceWorker.controller === worker) finish(resolve);
    };
    timer = setTimeout(
      () => finish(() => reject(new SteveError({
        code: "SERVICE_WORKER_UNAVAILABLE",
        stage: "registration",
        message: "Service worker is active but does not control this page"
      }))),
      CONTROLLER_TIMEOUT_MS
    );
    navigator.serviceWorker.addEventListener("controllerchange", onControllerChange);
    onControllerChange();
  });
}
var EnclaveClient = class {
  constructor(registration) {
    this.registration = registration;
    this.listeners = /* @__PURE__ */ new Map();
    navigator.serviceWorker.addEventListener("message", (event) => {
      if (event.data?.type?.startsWith("enclave:")) {
        const eventType = event.data.type.replace("enclave:", "");
        this.emit(eventType, event.data);
      }
    });
  }
  on(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, /* @__PURE__ */ new Set());
    }
    this.listeners.get(event).add(callback);
    return () => this.off(event, callback);
  }
  off(event, callback) {
    this.listeners.get(event)?.delete(callback);
  }
  emit(event, data) {
    this.listeners.get(event)?.forEach((cb) => cb(data));
    this.listeners.get("*")?.forEach((cb) => cb(event, data));
  }
  async sendMessage(type, data = {}, timeout = 1e4) {
    const controller = navigator.serviceWorker.controller;
    if (!controller) {
      throw new SteveError({
        code: "SERVICE_WORKER_UNAVAILABLE",
        stage: "service-worker",
        message: "Service worker does not control this page"
      });
    }
    return new Promise((resolve, reject) => {
      const channel = new MessageChannel();
      let settled = false;
      const settle = (callback, value) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        channel.port1.onmessage = null;
        channel.port1.close?.();
        callback(value);
      };
      channel.port1.onmessage = (event) => {
        if (event.data.success === false) {
          settle(reject, new SteveError(event.data.error));
        } else {
          settle(resolve, event.data);
        }
      };
      const timer = setTimeout(
        () => settle(reject, new SteveError({
          code: "MESSAGE_TIMEOUT",
          stage: "service-worker",
          message: "Message timeout"
        })),
        timeout
      );
      controller.postMessage(
        { type, ...data },
        [channel.port2]
      );
    });
  }
  async getStatus() {
    return this.sendMessage("get-status");
  }
  async initialize() {
    return (await this.sendMessage("initialize", {}, 15e3)).status;
  }
  async rotateSession() {
    return (await this.sendMessage("rotate-session", {}, 15e3)).status;
  }
  async rotateKey() {
    return this.rotateSession();
  }
  async reset() {
    return (await this.sendMessage("reset")).status;
  }
  async configure(config) {
    return this.sendMessage("configure", { config });
  }
  async send(path, options = {}) {
    const request = await serializeProtectedRequest(path, options);
    const result = await this.sendMessage(
      "protected-send",
      { request },
      PROTECTED_SEND_TIMEOUT_MS
    );
    const body = result.body instanceof Uint8Array && result.body.length > 0 ? result.body : null;
    return {
      response: new Response(body, {
        status: result.status,
        headers: result.headers
      }),
      sessionId: result.sessionId,
      exchange: result.exchange
    };
  }
  async getPcrPolicy() {
    return (await this.sendMessage("get-pcr-policy")).policy;
  }
  async replacePcrPolicy(policy) {
    const result = await this.sendMessage("replace-pcr-policy", { policy });
    return { policy: result.policy, status: result.status };
  }
  async waitForInitialization(timeout = 3e4) {
    const status = await this.getStatus();
    if (status.initialized) {
      return status;
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(new SteveError({
          code: "INITIALIZATION_TIMEOUT",
          stage: "initialization",
          message: "Initialization timeout"
        }));
      }, timeout);
      const onInitialized = (data) => {
        cleanup();
        resolve(data);
      };
      const onError = (data) => {
        if (data.operation === "initialization" || data.stage === "initialization") {
          cleanup();
          reject(new SteveError(data));
        }
      };
      const cleanup = () => {
        clearTimeout(timer);
        this.off("initialized", onInitialized);
        this.off("error", onError);
      };
      this.on("initialized", onInitialized);
      this.on("error", onError);
    });
  }
};
async function serializeProtectedRequest(path, options) {
  if (typeof path !== "string" || !path.startsWith("/") || path.startsWith("//")) {
    throw new SteveError({
      code: "INVALID_REQUEST",
      stage: "request",
      message: "protected request path must be relative"
    });
  }
  const url = new URL(path, "https://steve.invalid/");
  if (url.origin !== "https://steve.invalid" || url.hash) {
    throw new SteveError({
      code: "INVALID_REQUEST",
      stage: "request",
      message: "protected request path must be relative"
    });
  }
  if (!options || typeof options !== "object" || Array.isArray(options)) {
    throw new SteveError({
      code: "INVALID_REQUEST",
      stage: "request",
      message: "protected request options must be an object"
    });
  }
  const allowed = /* @__PURE__ */ new Set(["method", "headers", "body"]);
  for (const key of Object.keys(options)) {
    if (!allowed.has(key)) {
      throw new SteveError({
        code: "INVALID_REQUEST",
        stage: "request",
        message: `unsupported protected request option: ${key}`
      });
    }
  }
  let request;
  try {
    request = new Request(url, {
      method: options.method || "GET",
      headers: options.headers,
      body: options.body,
      credentials: "omit",
      redirect: "error"
    });
  } catch (cause) {
    throw new SteveError({
      code: "INVALID_REQUEST",
      stage: "request",
      message: cause instanceof Error ? cause.message : "protected request is invalid"
    });
  }
  return {
    path: url.pathname + url.search,
    method: request.method,
    headers: [...request.headers.entries()],
    body: new Uint8Array(await request.arrayBuffer())
  };
}
export {
  EnclaveClient,
  SteveError,
  registerEnclaveServiceWorker
};
