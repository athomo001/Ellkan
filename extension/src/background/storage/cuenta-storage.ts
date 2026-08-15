// Autor: Athan Espinoza

// Tier nuevo de storage (2026-08-15, spec 06 §3 extendida): servidor + email
// en `storage.local`, permanente — a diferencia de `sesion-storage.ts`
// (`storage.session`, se borra sola al cerrar el navegador), esto sobrevive
// reinicios a propósito. Se escribe una única vez en el primer login
// exitoso y nunca se vuelve a pedir en el formulario mientras exista; sólo
// el logout explícito lo purga (`AuthService.logout`) — nunca un lock por
// inactividad ni un reinicio de navegador, esos flujos lo leen tal cual.
//
// `locked_reason` viaja en el mismo tier por la misma razón: tiene que
// sobrevivir a que `LockService` limpie `storage.session` para forzar el
// re-lock (spec 06 §2, `chrome.alarms`) y seguir legible cuando el popup se
// reabre para decidir qué pantalla mostrar.

import { BrowserApi } from '../../browser-api';

const CLAVE = 'ellkan.cuenta';

interface CuentaPersistida {
	server_url: string;
	email: string;
	locked_reason?: 'inactividad';
}

export const CuentaStorage = {
	async leer(): Promise<CuentaPersistida | null> {
		const r = await BrowserApi.storageLocalGet<Record<string, CuentaPersistida>>(CLAVE);
		return r[CLAVE] ?? null;
	},

	/** No pisa una cuenta ya guardada — sólo se llama tras un login exitoso,
	 * y `AuthService` ya decide de antemano si corresponde escribir. */
	async guardar(serverUrl: string, email: string): Promise<void> {
		await BrowserApi.storageLocalSet({ [CLAVE]: { server_url: serverUrl, email } as CuentaPersistida });
	},

	async marcarBloqueadaPorInactividad(): Promise<void> {
		const actual = await CuentaStorage.leer();
		if (!actual) return; // nada que bloquear si nunca hubo login
		await BrowserApi.storageLocalSet({ [CLAVE]: { ...actual, locked_reason: 'inactividad' } as CuentaPersistida });
	},

	async limpiarMarcaDeBloqueo(): Promise<void> {
		const actual = await CuentaStorage.leer();
		if (!actual?.locked_reason) return;
		const { locked_reason: _descartado, ...resto } = actual;
		await BrowserApi.storageLocalSet({ [CLAVE]: resto as CuentaPersistida });
	},

	/** Purga total — sólo desde `AuthService.logout()` (cierre de sesión
	 * explícito y deliberado), nunca desde un lock. */
	async purgar(): Promise<void> {
		await BrowserApi.storageLocalRemove(CLAVE);
	}
};
