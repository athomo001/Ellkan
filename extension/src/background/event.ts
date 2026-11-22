// Autor: Athan Espinoza

// Event: registra los listeners sobre un `Port` ya autenticado por
// `Pagemod`/`PortManager`, y enruta cada request a su Controller (spec 06
// §2) — protocolo `Port.request()`: `requestId` (uuid) de correlación,
// respuesta `[requestId, "SUCCESS"|"ERROR", ...]`.

import type { MensajeRequest, MensajeResponse, WorkerName } from './types';
import { SesionController } from './controllers/sesion-controller';
import { AuthController } from './controllers/auth-controller';
import { VaultController } from './controllers/vault-controller';
import { AutofillController } from './controllers/autofill-controller';
import { TotpLocalController } from './controllers/totp-local-controller';
import { LockService } from './services/lock-service';
import { appEscritorioDisponible } from './transporte';
import { hrefDelRemitente, revelarSiCorrespondeALaPagina, rutaPermitida } from './rutas-permitidas';

type Handler = (payload: unknown) => Promise<unknown>;

// Un dominio funcional por carpeta (`controllers/autofill`, `controllers/
// sharing`, etc., spec 06 §2).
const rutas: Record<string, Handler> = {
	PING: () => SesionController.ping(),
	// F-56: ¿está la app de escritorio de este equipo (native messaging)?
	APP_ESCRITORIO_DISPONIBLE: () => appEscritorioDisponible(),
	AUTH_LOGIN: (payload) => AuthController.login(payload),
	AUTH_VERIFICAR_DISPOSITIVO: (payload) => AuthController.verificarDispositivo(payload),
	AUTH_VERIFICAR_MFA: (payload) => AuthController.verificarMfa(payload),
	AUTH_ESTADO_SESION: () => AuthController.estadoSesion(),
	AUTH_ESTADO_CUENTA: () => AuthController.estadoCuenta(),
	AUTH_LIMPIAR_MARCA_BLOQUEO: () => AuthController.limpiarMarcaDeBloqueo(),
	AUTH_ESTADO_PENDIENTE_DISPOSITIVO: () => AuthController.estadoPendienteDispositivo(),
	AUTH_CANCELAR_PENDIENTE_DISPOSITIVO: () => AuthController.cancelarPendienteDispositivo(),
	AUTH_LOGOUT: () => AuthController.logout(),
	VAULT_LISTAR: () => VaultController.listar(),
	VAULT_REVELAR_SECRETO: (payload) => VaultController.revelarSecreto(payload),
	VAULT_CREAR: (payload) => VaultController.crear(payload),
	VAULT_EDITAR: (payload) => VaultController.editar(payload),
	AUTOFILL_BUSCAR: (payload) => AutofillController.buscarCoincidencias(payload),
	// F-38 (desbloqueo rápido local con TOTP) — spec 05 §2.1.
	F38_ESTADO: () => TotpLocalController.estado(),
	F38_GENERAR_SETUP: () => TotpLocalController.generarSetup(),
	F38_CONFIRMAR: (payload) => TotpLocalController.confirmar(payload),
	F38_DESACTIVAR: () => TotpLocalController.desactivar(),
	F38_DESBLOQUEAR: (payload) => TotpLocalController.desbloquear(payload)
};

/**
 * QA-32: para un content script, la página que pide es la del frame según el
 * navegador (`sender.url`), nunca la que manda el propio script: el autofill
 * busca coincidencias para esa URL y el secreto sólo sale si el recurso
 * coincide con ella.
 */
function rutasDeContent(port: chrome.runtime.Port): Record<string, Handler> {
	const urlRemitente = port.sender?.url;
	const href = (payload: unknown) => hrefDelRemitente((payload as { href?: unknown } | undefined)?.href, urlRemitente);
	return {
		AUTOFILL_BUSCAR: (payload) => AutofillController.buscarCoincidencias({ href: href(payload) }),
		VAULT_REVELAR_SECRETO: (payload) => {
			const resourceId = (payload as { resourceId?: unknown } | undefined)?.resourceId;
			if (typeof resourceId !== 'string' || !resourceId) throw new Error('falta resourceId');
			return revelarSiCorrespondeALaPagina(
				resourceId,
				href(payload),
				(href) => AutofillController.buscarCoincidencias({ href }),
				() => VaultController.revelarSecreto({ resourceId })
			);
		},
		VAULT_CREAR: rutas.VAULT_CREAR
	};
}

export function registrarEventos(port: chrome.runtime.Port, worker: WorkerName): void {
	const propias = worker === 'QuickAccess' ? rutas : rutasDeContent(port);
	port.onMessage.addListener(async (mensaje: MensajeRequest) => {
		if (mensaje.tipo === 'HANDSHAKE') return; // ya consumido por Pagemod

		// Cualquier mensaje real por un puerto ya autenticado cuenta como
		// actividad (2026-08-15) — reprograma el timeout de inactividad de
		// F-04, no sólo abrir el popup.
		LockService.registrarActividad();

		const handler = rutaPermitida(worker, mensaje.tipo) ? propias[mensaje.tipo] : undefined;
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
