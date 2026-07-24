const CONTROLLER_TIMEOUT_MS = 5000;

export async function registerEnclaveServiceWorker(options = {}) {
  if (!('serviceWorker' in navigator)) {
    throw new Error('Service workers not supported');
  }

  const swPath = options.swPath || '/enclave-sw.js';
  const scope = options.scope || '/';

  const registration = await navigator.serviceWorker.register(swPath, { scope });
  const worker = registration.installing || registration.waiting || registration.active;
  if (!worker) throw new Error('Service worker registration has no worker');
  await waitForActivation(worker);
  await waitForController(worker);

  const client = new EnclaveClient(registration);

  if (options.config) {
    await client.configure(options.config);
  }

  return client;
}

function waitForActivation(worker) {
  if (worker.state === 'activated') return Promise.resolve();
  return new Promise((resolve, reject) => {
    let timer;
    const finish = callback => {
      clearTimeout(timer);
      worker.removeEventListener('statechange', onStateChange);
      callback();
    };
    const onStateChange = () => {
      if (worker.state === 'activated') {
        finish(resolve);
      } else if (worker.state === 'redundant') {
        finish(() => reject(new Error('Service worker installation failed')));
      }
    };
    timer = setTimeout(
      () => finish(() => reject(
        new Error('Service worker activation timed out')
      )),
      CONTROLLER_TIMEOUT_MS
    );
    worker.addEventListener('statechange', onStateChange);
    onStateChange();
  });
}

function waitForController(worker) {
  if (navigator.serviceWorker.controller === worker) return Promise.resolve();
  return new Promise((resolve, reject) => {
    let timer;
    const finish = callback => {
      clearTimeout(timer);
      navigator.serviceWorker.removeEventListener('controllerchange', onControllerChange);
      callback();
    };
    const onControllerChange = () => {
      if (navigator.serviceWorker.controller === worker) finish(resolve);
    };
    timer = setTimeout(
      () => finish(() => reject(
        new Error('Service worker is active but does not control this page')
      )),
      CONTROLLER_TIMEOUT_MS
    );
    navigator.serviceWorker.addEventListener('controllerchange', onControllerChange);
    onControllerChange();
  });
}

export class EnclaveClient {
  constructor(registration) {
    this.registration = registration;
    this.listeners = new Map();

    navigator.serviceWorker.addEventListener('message', (event) => {
      if (event.data?.type?.startsWith('enclave:')) {
        const eventType = event.data.type.replace('enclave:', '');
        this.emit(eventType, event.data);
      }
    });
  }

  on(event, callback) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event).add(callback);
    return () => this.off(event, callback);
  }

  off(event, callback) {
    this.listeners.get(event)?.delete(callback);
  }

  emit(event, data) {
    this.listeners.get(event)?.forEach(cb => cb(data));
    this.listeners.get('*')?.forEach(cb => cb(event, data));
  }

  async sendMessage(type, data = {}, timeout = 10000) {
    const controller = navigator.serviceWorker.controller;
    if (!controller) {
      throw new Error('Service worker does not control this page');
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
        if (event.data.error) {
          settle(reject, new Error(event.data.error));
        } else {
          settle(resolve, event.data);
        }
      };

      const timer = setTimeout(
        () => settle(reject, new Error('Message timeout')),
        timeout
      );

      controller.postMessage(
        { type, ...data },
        [channel.port2]
      );
    });
  }

  async getStatus() {
    return this.sendMessage('get-status');
  }

  async initialize() {
    return this.sendMessage('initialize', {}, 15000);
  }

  async rotateKey() {
    return this.sendMessage('rotate-key', {}, 15000);
  }

  async reset() {
    return this.sendMessage('reset');
  }

  async configure(config) {
    return this.sendMessage('configure', { config });
  }

  async waitForInitialization(timeout = 30000) {
    const status = await this.getStatus();
    if (status.initialized) {
      return status;
    }

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error('Initialization timeout'));
      }, timeout);

      const onInitialized = (data) => {
        cleanup();
        resolve(data);
      };

      const onError = (data) => {
        if (data.stage === 'initialization') {
          cleanup();
          reject(new Error(data.message));
        }
      };

      const cleanup = () => {
        clearTimeout(timer);
        this.off('initialized', onInitialized);
        this.off('error', onError);
      };

      this.on('initialized', onInitialized);
      this.on('error', onError);
    });
  }
}
