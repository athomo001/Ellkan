//#region src/browser-api.ts
var globalConBrowser = globalThis;
/** Firefox y Safari exponen `browser.*`; Chromium (y derivados) sólo `chrome.*`. */
var esFirefox = navigator.userAgent.includes("Firefox");
var esSafariApi = typeof globalConBrowser.browser !== "undefined" && !esFirefox;
/** Namespace real a usar — `browser.*` donde exista (promesas nativas),
* `chrome.*` en Chromium. Nunca se expone directo: todo pasa por los
* métodos de abajo. */
var api = globalConBrowser.browser ?? chrome;
var BrowserApi = {
	esFirefox,
	esSafariApi,
	getRuntimeURL(path) {
		return api.runtime.getURL(path);
	},
	async tabsQuery(query) {
		return api.tabs.query(query);
	},
	connect(connectInfo) {
		return api.runtime.connect(connectInfo);
	},
	onConnect(listener) {
		api.runtime.onConnect.addListener(listener);
	},
	async storageSessionGet(keys) {
		return await api.storage.session.get(keys);
	},
	async storageSessionSet(items) {
		await api.storage.session.set(items);
	},
	async storageSessionRemove(keys) {
		await api.storage.session.remove(keys);
	},
	async storageLocalGet(keys) {
		return await api.storage.local.get(keys);
	},
	async storageLocalSet(items) {
		await api.storage.local.set(items);
	},
	async storageLocalRemove(keys) {
		await api.storage.local.remove(keys);
	},
	/** `chrome.alarms`, nunca `setTimeout`/`setInterval` a solas (spec 06 §2)
	* — un timer en el service worker se pierde si el navegador lo termina
	* por inactividad; una alarma persiste a nivel de navegador. */
	createAlarm(name, alarmInfo) {
		api.alarms.create(name, alarmInfo);
	},
	onAlarm(listener) {
		api.alarms.onAlarm.addListener(listener);
	},
	async clearAlarm(name) {
		return api.alarms.clear(name);
	}
};
//#endregion
export { BrowserApi as t };
