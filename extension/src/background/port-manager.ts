// Autor: Athan Espinoza

// Ciclo de vida de los `runtime.Port` + anti-spoofing (spec 05 §2.1, spec 06
// §2) — antes de aceptar cualquier (re)conexión sobre un `workerId` ya
// conocido, se valida que `tabId`+`frameId` coincidan exactamente con los
// registrados para ese worker. Sin esto, un frame arbitrario de la página
// visitada podría intentar secuestrar un canal ya establecido con la
// extensión. Mismo criterio que `PortManager.isKnownPortSender()` de
// Passbolt — se prefiere sobre el "secreto por pestaña" de Bitwarden porque
// cubre el mismo riesgo con menos superficie propia.

import type { WorkerInfo, WorkerName } from './types';

interface WorkerRegistrado extends WorkerInfo {
	port: chrome.runtime.Port;
}

class PortManagerImpl {
	private workers = new Map<string, WorkerRegistrado>();

	/** `true` si `port` viene exactamente del mismo `tabId`+`frameId` que el
	 * worker ya registrado bajo `workerId` — la única condición que hace
	 * válida una reconexión sobre un id conocido. No aplica a `QuickAccess`
	 * (ver `registrar`), que nunca tiene tabId/frameId que comparar. */
	private esRemitenteConocido(workerId: string, port: chrome.runtime.Port): boolean {
		const existente = this.workers.get(workerId);
		if (!existente) return true; // id nuevo, no hay nada que spoofear todavía
		const sender = port.sender;
		if (!sender || sender.tab?.id === undefined || sender.frameId === undefined) return false;
		return sender.tab.id === existente.tabId && sender.frameId === existente.frameId;
	}

	/** Registra (o rechaza) una conexión entrante. `port.name` es el
	 * `workerId` — mismo convenio que Passbolt (uuid generado por el content
	 * script al conectar). Devuelve `null` si la conexión se rechazó por
	 * anti-spoofing: el caller debe desconectar el puerto sin registrar nada. */
	registrar(port: chrome.runtime.Port, name: WorkerName): WorkerInfo | null {
		const workerId = port.name;
		const sender = port.sender;
		if (!sender) return null;

		// QuickAccess es el popup de la extensión, no un content script
		// inyectado en una página ajena — nunca tiene `sender.tab` (chrome no
		// lo setea para conexiones desde popup/options), así que el chequeo de
		// tabId/frameId de abajo no aplica y rechazaría SIEMPRE una conexión
		// legítima (bug real: timeout de "ellkan.port.ready" reportado por el
		// usuario, el popup nunca lograba loguearse aunque el backend
		// estuviera arriba). Lo que sí hay que verificar es que el remitente
		// sea la extensión misma: `sender.id` lo pone chrome de forma
		// autoritativa, ninguna página puede falsificarlo.
		if (name === 'QuickAccess') {
			if (sender.id !== chrome.runtime.id || sender.tab !== undefined) return null;
			const info: WorkerRegistrado = { id: workerId, tabId: undefined, frameId: undefined, name, status: 'connected', port };
			this.workers.set(workerId, info);
			port.onDisconnect.addListener(() => {
				const actual = this.workers.get(workerId);
				if (actual?.port === port) actual.status = 'disconnected';
			});
			return { id: info.id, tabId: info.tabId, frameId: info.frameId, name: info.name, status: info.status };
		}

		if (sender.tab?.id === undefined || sender.frameId === undefined) return null;

		if (!this.esRemitenteConocido(workerId, port)) {
			// Alguien más (u otro frame) ya es dueño de este workerId — no se
			// pisa el registro existente, se rechaza la conexión nueva.
			return null;
		}

		const info: WorkerRegistrado = {
			id: workerId,
			tabId: sender.tab.id,
			frameId: sender.frameId,
			name,
			status: 'connected',
			port
		};
		this.workers.set(workerId, info);

		port.onDisconnect.addListener(() => {
			const actual = this.workers.get(workerId);
			if (actual?.port === port) actual.status = 'disconnected';
		});

		return { id: info.id, tabId: info.tabId, frameId: info.frameId, name: info.name, status: info.status };
	}

	/** El puerto vivo para `workerId`, o `undefined` si el service worker
	 * fue terminado por inactividad (MV3) y todavía no reconectó — el
	 * caller debe pedirle al content script que reabra la conexión
	 * (`ellkan.port.connect`, spec 06 §2) en vez de asumir que sigue ahí. */
	get(workerId: string): chrome.runtime.Port | undefined {
		const worker = this.workers.get(workerId);
		return worker?.status === 'connected' ? worker.port : undefined;
	}

	desconectar(workerId: string): void {
		this.workers.delete(workerId);
	}
}

export const PortManager = new PortManagerImpl();
