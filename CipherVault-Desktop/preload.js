const { contextBridge, ipcRenderer } = require('electron');

/**
 * The only bridge between the vault UI and the main process.
 *
 * The renderer runs with contextIsolation and sandbox on and has no Node
 * access, which is what we want for a page that holds decrypted secrets. This
 * exposes exactly the update surface it needs and nothing else: no filesystem,
 * no shell, no arbitrary IPC. Every channel name is fixed here rather than
 * passed in by the caller, so the page cannot reach a channel we did not intend
 * to publish.
 */
const UPDATE_EVENTS = [
  'checking',
  'available',
  'not-available',
  'progress',
  'downloaded',
  'error',
];

contextBridge.exposeInMainWorld('cipherVaultDesktop', {
  isDesktop: true,

  /** Version of the installed app, from package.json at build time. */
  getVersion: () => ipcRenderer.invoke('app:get-version'),

  update: {
    /** Ask GitHub whether a newer release exists. Resolves to a summary. */
    check: () => ipcRenderer.invoke('update:check'),

    /** Start downloading the update that `check` reported. */
    download: () => ipcRenderer.invoke('update:download'),

    /** Quit and run the installer. Does not return. */
    install: () => ipcRenderer.invoke('update:install'),

    /**
     * Subscribe to update lifecycle events.
     * @param {(event: string, payload: object) => void} callback
     * @returns {() => void} unsubscribe
     */
    on: (callback) => {
      if (typeof callback !== 'function') return () => {};

      const handlers = UPDATE_EVENTS.map((name) => {
        const channel = `update:${name}`;
        // Deliberately drop Electron's IpcRendererEvent: handing the renderer
        // a live sender object would widen this bridge well beyond updates.
        const handler = (_event, payload) => callback(name, payload || {});
        ipcRenderer.on(channel, handler);
        return () => ipcRenderer.removeListener(channel, handler);
      });

      return () => handlers.forEach((off) => off());
    },
  },
});
