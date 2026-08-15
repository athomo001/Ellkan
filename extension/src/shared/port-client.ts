// Autor: Athan Espinoza

// Cliente del protocolo de puertos (spec 06 §2), usado tanto por el content
// script como por el popup — cualquier superficie que necesite pedirle algo
// al service worker vía `runtime.Port`. Usa `chrome.runtime.*` nativo
// directo en vez de `BrowserApi`: en el content script es la excepción
// documentada de esa regla (no puede arrastrar el bundle completo de la app
// al contexto de la página anfitriona); en el popup no hay tal restricción,
// pero se reusa el mismo cliente para no mantener dos implementaciones del
// mismo protocolo de reconexión/anti-spoofing.

import type { MensajeRequest, MensajeResponse, WorkerName } from '../background/types';

const MAX_REINTENTOS_RECONEXION = 50;
const INTERVALO_REINTENTO_MS = 100;

export class PortClient {
	private port: chrome.runtime.Port | null = null;
	private readonly workerId = crypto.randomUUID();
	private readonly pendientes = new Map<string, { resolve: (v: unknown) => void; reject: (e: Error) => void }>();
	private listo: Promise<void> | null = null;

	constructor(private readonly nombre: WorkerName) {}

	async conectar(): Promise<void> {
		if (this.listo) return this.listo;
		this.listo = this.abrirYHandshake();
		return this.listo;
	}

	private abrirYHandshake(): Promise<void> {
		return new Promise((resolve, reject) => {
			const port = chrome.runtime.connect({ name: this.workerId });
			this.port = port;

			const timeout = setTimeout(() => reject(new Error('timeout esperando ellkan.port.ready')), INTERVALO_REINTENTO_MS * 5);

			port.onMessage.addListener((mensaje: unknown) => {
				if (Array.isArray(mensaje) && mensaje[0] === 'ellkan.port.ready') {
					clearTimeout(timeout);
					resolve();
					return;
				}
				if (Array.isArray(mensaje) && mensaje[0] === 'ellkan.port.connect') {
					// El service worker se reinició (MV3) y perdió el puerto —
					// reabre con reintentos acotados (spec 06 §2).
					this.reconectarConReintentos();
					return;
				}
				this.despacharRespuesta(mensaje as MensajeResponse);
			});

			port.onDisconnect.addListener(() => {
				this.port = null;
				this.listo = null;
			});

			const handshake: MensajeRequest = {
				requestId: crypto.randomUUID(),
				tipo: 'HANDSHAKE',
				payload: { name: this.nombre }
			};
			port.postMessage(handshake);
		});
	}

	private async reconectarConReintentos(): Promise<void> {
		for (let intento = 0; intento < MAX_REINTENTOS_RECONEXION; intento++) {
			try {
				this.listo = null;
				await this.conectar();
				return;
			} catch {
				await new Promise((r) => setTimeout(r, INTERVALO_REINTENTO_MS));
			}
		}
	}

	private despacharRespuesta(mensaje: MensajeResponse): void {
		if (!Array.isArray(mensaje) || mensaje.length < 2) return;
		const [requestId, estado] = mensaje;
		const pendiente = this.pendientes.get(requestId);
		if (!pendiente) return;
		this.pendientes.delete(requestId);
		if (estado === 'SUCCESS') pendiente.resolve(mensaje[2]);
		else pendiente.reject(new Error(typeof mensaje[2] === 'string' ? mensaje[2] : 'error desconocido'));
	}

	async request<T = unknown>(tipo: string, payload?: unknown): Promise<T> {
		await this.conectar();
		const requestId = crypto.randomUUID();
		const mensaje: MensajeRequest = { requestId, tipo, payload };
		return new Promise<T>((resolve, reject) => {
			this.pendientes.set(requestId, { resolve: resolve as (v: unknown) => void, reject });
			this.port!.postMessage(mensaje);
		});
	}
}
