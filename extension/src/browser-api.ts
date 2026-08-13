// Autor: Athan Espinoza

// Única capa de abstracción runtime (spec 06 §1/§7) — nada fuera de este
// archivo (salvo los content scripts, ver excepción documentada en la spec)
// llama `chrome.*`/`browser.*` directamente. Detecta en runtime con qué
// navegador está corriendo y expone las diferencias reales como métodos.

const globalConBrowser = globalThis as typeof globalThis & { browser?: typeof chrome };

/** Firefox y Safari exponen `browser.*`; Chromium (y derivados) sólo `chrome.*`. */
export const esFirefox = navigator.userAgent.includes('Firefox');
export const esSafariApi = typeof globalConBrowser.browser !== 'undefined' && !esFirefox;

/** Namespace real a usar — `browser.*` donde exista (promesas nativas),
 * `chrome.*` en Chromium. Nunca se expone directo: todo pasa por los
 * métodos de abajo. */
const api: typeof chrome = globalConBrowser.browser ?? chrome;

export const BrowserApi = {
	esFirefox,
	esSafariApi,

	getRuntimeURL(path: string): string {
		return api.runtime.getURL(path);
	},

	async tabsQuery(query: chrome.tabs.QueryInfo): Promise<chrome.tabs.Tab[]> {
		return api.tabs.query(query);
	},

	connect(connectInfo: chrome.runtime.ConnectInfo): chrome.runtime.Port {
		return api.runtime.connect(connectInfo);
	},

	onConnect(listener: (port: chrome.runtime.Port) => void): void {
		api.runtime.onConnect.addListener(listener);
	},

	async storageSessionGet<T = Record<string, unknown>>(keys: string | string[] | null): Promise<T> {
		// El overload genérico de `@types/chrome` espera `keyof T`, que no se
		// puede conocer acá (T lo decide cada caller) — cast puntual, la forma
		// real de `keys` en runtime es la misma de siempre (string|string[]|null).
		return (await api.storage.session.get(keys as any)) as T;
	},

	async storageSessionSet(items: Record<string, unknown>): Promise<void> {
		await api.storage.session.set(items);
	},

	async storageSessionRemove(keys: string | string[]): Promise<void> {
		await api.storage.session.remove(keys);
	},

	async storageLocalGet<T = Record<string, unknown>>(keys: string | string[] | null): Promise<T> {
		return (await api.storage.local.get(keys as any)) as T;
	},

	async storageLocalSet(items: Record<string, unknown>): Promise<void> {
		await api.storage.local.set(items);
	},

	async storageLocalRemove(keys: string | string[]): Promise<void> {
		await api.storage.local.remove(keys);
	},

	/** `chrome.alarms`, nunca `setTimeout`/`setInterval` a solas (spec 06 §2)
	 * — un timer en el service worker se pierde si el navegador lo termina
	 * por inactividad; una alarma persiste a nivel de navegador. */
	createAlarm(name: string, alarmInfo: chrome.alarms.AlarmCreateInfo): void {
		api.alarms.create(name, alarmInfo);
	},

	onAlarm(listener: (alarm: chrome.alarms.Alarm) => void): void {
		api.alarms.onAlarm.addListener(listener);
	},

	async clearAlarm(name: string): Promise<boolean> {
		return api.alarms.clear(name);
	}
};
