// Autor: Athan Espinoza

// Event: registra los listeners sobre un `Port` ya autenticado por
// `Pagemod`/`PortManager`, y enruta cada request a su Controller (spec 06
// §2) — protocolo `Port.request()`: `requestId` (uuid) de correlación,
// respuesta `[requestId, "SUCCESS"|"ERROR", ...]`.

import type { MensajeRequest, MensajeResponse } from './types';
import { SesionController } from './controllers/sesion-controller';
import { AuthController } from './controllers/auth-controller';
import { VaultController } from './controllers/vault-controller';
import { AutofillController } from './controllers/autofill-controller';

type Handler = (payload: unknown) => Promise<unknown>;

// Un dominio funcional por carpeta (`controllers/autofill`, `controllers/
// sharing`, etc., spec 06 §2).
const rutas: Record<string, Handler> = {
	PING: () => SesionController.ping(),
	AUTH_LOGIN: (payload) => AuthController.login(payload),
	AUTH_VERIFICAR_DISPOSITIVO: (payload) => AuthController.verificarDispositivo(payload),
	AUTH_ESTADO_SESION: () => AuthController.estadoSesion(),
	AUTH_ESTADO_PENDIENTE_DISPOSITIVO: () => AuthController.estadoPendienteDispositivo(),
	AUTH_CANCELAR_PENDIENTE_DISPOSITIVO: () => AuthController.cancelarPendienteDispositivo(),
	AUTH_LOGOUT: () => AuthController.logout(),
	VAULT_LISTAR: () => VaultController.listar(),
	VAULT_REVELAR_SECRETO: (payload) => VaultController.revelarSecreto(payload),
	VAULT_CREAR: (payload) => VaultController.crear(payload),
	VAULT_EDITAR: (payload) => VaultController.editar(payload),
	AUTOFILL_BUSCAR: (payload) => AutofillController.buscarCoincidencias(payload)
};

export function registrarEventos(port: chrome.runtime.Port): void {
	port.onMessage.addListener(async (mensaje: MensajeRequest) => {
		if (mensaje.tipo === 'HANDSHAKE') return; // ya consumido por Pagemod

		const handler = rutas[mensaje.tipo];
		if (!handler) {
			const respuesta: MensajeResponse = [mensaje.requestId, 'ERROR', `tipo de request desconocido: ${mensaje.tipo}`];
			port.postMessage(respuesta);
			return;
		}
		try {
			const resultado = await handler(mensaje.payload);
			const respuesta: MensajeResponse = [mensaje.requestId, 'SUCCESS', resultado];
			port.postMessage(respuesta);
		} catch (e) {
			const respuesta: MensajeResponse = [mensaje.requestId, 'ERROR', e instanceof Error ? e.message : String(e)];
			port.postMessage(respuesta);
		}
	});
}
