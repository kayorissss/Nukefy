'use strict';
const { contextBridge, ipcRenderer } = require('electron');

const invoke = (ch) => (...args) => ipcRenderer.invoke(ch, ...args);

contextBridge.exposeInMainWorld('nukefy', {
  state: invoke('app:state'),
  startScan: invoke('scan:start'),
  cancelScan: invoke('scan:cancel'),
  systemCheck: invoke('system:check'),
  threats: invoke('threat:list'),
  act: invoke('threat:act'),
  knowledge: (id, fam) => ipcRenderer.invoke('threat:knowledge', id, fam),
  quarantineList: invoke('quarantine:list'),
  quarantineRestore: invoke('quarantine:restore'),
  quarantineRemove: invoke('quarantine:remove'),
  getSettings: invoke('settings:get'),
  setSettings: invoke('settings:set'),
  testVt: invoke('settings:testVt'),
  analyzeUrl: invoke('url:analyze'),
  pickFolders: invoke('files:pick'),
  openExternal: invoke('shell:openExternal'),
  reveal: invoke('shell:reveal'),
  openPath: invoke('shell:openPath'),
  selftest: invoke('misc:selftest'),
  setProtection: invoke('protection:set'),
  setAutostart: invoke('autostart:set'),
  quit: invoke('app:quit'),
  minimize: invoke('app:minimize'),
  toggleFull: invoke('app:toggleFull'),
  onEvent: (cb) => {
    const l = (_e, payload) => cb(payload);
    ipcRenderer.on('nukefy:evt', l);
    return () => ipcRenderer.removeListener('nukefy:evt', l);
  },
});
