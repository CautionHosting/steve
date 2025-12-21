// src/register.js
async function registerEnclaveServiceWorker(options = {}) {
  if (!("serviceWorker" in navigator)) {
    throw new Error("Service workers not supported");
  }
  const swPath = options.swPath || "/enclave-sw.js";
  const scope = options.scope || "/";
  const registration = await navigator.serviceWorker.register(swPath, { scope });
  if (registration.installing) {
    await new Promise((resolve) => {
      registration.installing.addEventListener("statechange", (e) => {
        if (e.target.state === "activated") resolve();
      });
    });
  }
  await navigator.serviceWorker.ready;
  const client = new EnclaveClient(registration);
  if (options.config) {
    await client.configure(options.config);
  }
  return client;
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
  async sendMessage(type, data = {}) {
    return new Promise((resolve, reject) => {
      const channel = new MessageChannel();
      channel.port1.onmessage = (event) => {
        if (event.data.error) {
          reject(new Error(event.data.error));
        } else {
          resolve(event.data);
        }
      };
      navigator.serviceWorker.controller?.postMessage(
        { type, ...data },
        [channel.port2]
      );
      setTimeout(() => reject(new Error("Message timeout")), 1e4);
    });
  }
  async getStatus() {
    return this.sendMessage("get-status");
  }
  async initialize() {
    return this.sendMessage("initialize");
  }
  async rotateKey() {
    return this.sendMessage("rotate-key");
  }
  async reset() {
    return this.sendMessage("reset");
  }
  async configure(config) {
    return this.sendMessage("configure", { config });
  }
  async waitForInitialization(timeout = 3e4) {
    const status = await this.getStatus();
    if (status.initialized) {
      return status;
    }
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error("Initialization timeout"));
      }, timeout);
      const onInitialized = (data) => {
        cleanup();
        resolve(data);
      };
      const onError = (data) => {
        if (data.stage === "initialization") {
          cleanup();
          reject(new Error(data.message));
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
export {
  EnclaveClient,
  registerEnclaveServiceWorker
};
