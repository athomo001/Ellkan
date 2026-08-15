// Autor: Athan Espinoza

// Pagemod: decide qué hacer con una conexión entrante de un content script
// (spec 06 §2). El primer mensaje sobre el puerto siempre es un handshake
// declarando el `WorkerName` (`WebIntegration`/`InFormMenu`/etc.) — recién
// ahí `PortManager.registrar()` puede validar anti-spoofing y completar el
// registro; antes de eso no hay todavía nada que un frame ajeno pudiera
// secuestrar.

import { PortManager } from './port-manager';
import { registrarEventos } from './event';
import type { MensajeRequest, WorkerName } from './types';

const NOMBRES_VALIDOS: readonly WorkerName[] = ['WebIntegration', 'InFormMenu', 'NotificationBar', 'QuickAccess'];

function esHandshakeValido(mensaje: unknown): mensaje is MensajeRequest & { payload: { name: WorkerName } } {
	if (typeof mensaje !== 'object' || mensaje === null) return false;
	const m = mensaje as Partial<MensajeRequest> & { payload?: { name?: unknown } };
	return m.tipo === 'HANDSHAKE' && typeof m.payload?.name === 'string' && NOMBRES_VALIDOS.includes(m.payload.name as WorkerName);
}

export function attachPagemod(port: chrome.runtime.Port): void {
	function alRecibirHandshake(mensaje: unknown): void {
		if (!esHandshakeValido(mensaje)) return; // ignora cualquier mensaje previo al handshake

		port.onMessage.removeListener(alRecibirHandshake);

		const info = PortManager.registrar(port, mensaje.payload.name);
		if (!info) {
			// Anti-spoofing: tabId/frameId no coinciden con el worker ya
			// registrado bajo este id, o el `sender` no trae la info mínima
			// necesaria para validar — se rechaza sin registrar nada.
			port.disconnect();
			return;
		}

		registrarEventos(port);
		port.postMessage(['ellkan.port.ready']);
	}

	port.onMessage.addListener(alRecibirHandshake);
}
