// Autor: Athan Espinoza

// Firefox y Safari exponen el namespace WebExtension estándar como
// `browser.*` (basado en promesas), forma equivalente a `chrome.*` para las
// APIs que usa `BrowserApi` (runtime/storage/tabs/alarms/idle) — se declara
// acá en vez de agregar un paquete de tipos nuevo sólo para esto.
declare const browser: typeof chrome;
