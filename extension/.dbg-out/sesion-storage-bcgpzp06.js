import { t as BrowserApi } from "./browser-api-Dqf8nftw.js";
//#region src/background/storage/sesion-storage.ts
var PREFIJO = "ellkan.sesion.";
var SesionStorage = {
	async guardar(clave, valor) {
		await BrowserApi.storageSessionSet({ [PREFIJO + clave]: valor });
	},
	async leer(clave) {
		return (await BrowserApi.storageSessionGet(PREFIJO + clave))[PREFIJO + clave] ?? null;
	},
	async limpiar(clave) {
		await BrowserApi.storageSessionRemove(PREFIJO + clave);
	}
};
//#endregion
export { SesionStorage };
