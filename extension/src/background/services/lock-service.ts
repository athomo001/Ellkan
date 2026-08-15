// Autor: Athan Espinoza

// Reglas de sesión inteligentes (2026-08-15): más de 6h continuas sin
// actividad bloquea la extensión y exige Contraseña Master + código MFA
// real (`AuthService.login(..., forceMfa: true)`, ver `backend/src/auth/
// service.rs::resolver_tras_f02`) — nunca vuelve a pedir servidor/email,
// esos ya quedaron en `CuentaStorage` desde el primer login. Un reinicio de
// navegador NO pasa por acá: `storage.session` ya se borra sola (spec 06
// §3), y el popup lo distingue de un lock por inactividad porque
// `CuentaStorage.locked_reason` sólo lo pone esta alarma, nunca el
// navegador.
//
// `chrome.alarms`, no `setTimeout` a solas (spec 06 §2) — un timer del
// service worker no sobrevive a que MV3 lo termine por inactividad, una
// alarma sí.

import { BrowserApi } from '../../browser-api';
import { CuentaStorage } from '../storage/cuenta-storage';
import { SesionStorage } from '../storage/sesion-storage';

const ALARMA = 'ellkan.inactividad';
const MINUTOS_INACTIVIDAD = 360; // 6h

export const LockService = {
	/** Se llama en cada mensaje de puerto ya autenticado (`event.ts`) —
	 * reprograma la alarma, "actividad" es cualquier uso real de la
	 * extensión, no sólo abrir el popup. */
	registrarActividad(): void {
		BrowserApi.createAlarm(ALARMA, { delayInMinutes: MINUTOS_INACTIVIDAD });
	},

	async cancelar(): Promise<void> {
		await BrowserApi.clearAlarm(ALARMA);
	},

	/** Registrado una sola vez en `background/index.ts`. Si dispara con el
	 * service worker dormido, `chrome.alarms` lo despierta solo — no depende
	 * de que el popup esté abierto en ese momento. */
	instalarListener(): void {
		BrowserApi.onAlarm(async (alarm) => {
			if (alarm.name !== ALARMA) return;
			await CuentaStorage.marcarBloqueadaPorInactividad();
			for (const clave of ['session_id', 'user_id', 'x25519_private', 'ed25519_private', 'device_challenge_id']) {
				await SesionStorage.limpiar(clave);
			}
		});
	}
};
