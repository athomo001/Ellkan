// Autor: Athan Espinoza

// F-56, fase 1: cómo le llegan los pedidos de la extensión a su servidor.
// - Servidor Ellkan (`https://…`): `fetch` de siempre.
// - App de escritorio de este equipo (`URL_APP_ESCRITORIO`): native messaging
//   con el host `com.ellkan.desktop`, que la app registró al arrancar. No hay
//   puerto TCP: el navegador le pasa los mensajes al host por stdin/stdout y
//   el host a la app por una tubería con nombre de este usuario. Antes era
//   `http://127.0.0.1:<puerto>`, en claro dentro de la máquina.
//
// La respuesta se devuelve como un `Response` normal, así el resto del código
// (auth-service, vault-service) no distingue un camino del otro.

import { BrowserApi } from '../browser-api';
import { bytesABase64, base64ABytes } from '../../../frontend/src/lib/crypto/b64';

/** "Servidor" que significa: la app de escritorio de este mismo equipo. */
export const URL_APP_ESCRITORIO = 'ellkan-app://este-equipo';

const NOMBRE_HOST = 'com.ellkan.desktop';
const ESPERA_MS = 30_000;

export function esAppEscritorio(serverUrl: string | null | undefined): boolean {
	return !!serverUrl && serverUrl.startsWith('ellkan-app:');
}

interface Pendiente {
	partes: string[];
	resolver: (v: RespuestaCanal) => void;
	rechazar: (e: Error) => void;
	reloj: ReturnType<typeof setTimeout>;
}

interface RespuestaCanal {
	ok?: boolean;
	status?: number;
	headers?: Record<string, string>;
	cuerpo_b64?: string;
	error?: string;
}

let puerto: chrome.runtime.Port | null = null;
let siguienteId = 1;
const pendientes = new Map<number, Pendiente>();

function mensajeDeError(codigo: string): string {
	switch (codigo) {
		case 'app_cerrada':
			return 'La app de escritorio de Ellkan no está abierta. Ábrela y vuelve a intentar.';
		case 'app_ocupada':
			return 'La app de escritorio de Ellkan está ocupada. Vuelve a intentar.';
		default:
			return codigo;
	}
}

function abrir(): chrome.runtime.Port {
	if (puerto) return puerto;
	const nuevo = BrowserApi.connectNative(NOMBRE_HOST);
	nuevo.onMessage.addListener((m: { id: number; parte: number; total: number; datos: string }) => {
		const p = pendientes.get(m.id);
		if (!p) return;
		p.partes[m.parte] = m.datos;
		// Respuestas grandes llegan en partes (el host no puede mandar más de 1 MB por mensaje).
		if (p.partes.filter((x) => x !== undefined).length < m.total) return;
		pendientes.delete(m.id);
		clearTimeout(p.reloj);
		try {
			p.resolver(JSON.parse(p.partes.join('')) as RespuestaCanal);
		} catch {
			p.rechazar(new Error('respuesta ilegible de la app de escritorio'));
		}
	});
	nuevo.onDisconnect.addListener(() => {
		// Sin host registrado (app nunca instalada en este equipo) o el host terminó.
		const motivo = (globalThis as { chrome?: typeof chrome }).chrome?.runtime?.lastError?.message;
		puerto = null;
		for (const [id, p] of pendientes) {
			clearTimeout(p.reloj);
			p.rechazar(new Error(motivo ? `No se pudo hablar con la app de escritorio: ${motivo}` : 'Se cortó el canal con la app de escritorio.'));
			pendientes.delete(id);
		}
	});
	puerto = nuevo;
	return nuevo;
}

function enviar(pedido: Record<string, unknown>): Promise<RespuestaCanal> {
	return new Promise((resolver, rechazar) => {
		const id = siguienteId++;
		const reloj = setTimeout(() => {
			pendientes.delete(id);
			rechazar(new Error('La app de escritorio no respondió a tiempo.'));
		}, ESPERA_MS);
		pendientes.set(id, { partes: [], resolver, rechazar, reloj });
		try {
			abrir().postMessage({ id, ...pedido });
		} catch (err) {
			clearTimeout(reloj);
			pendientes.delete(id);
			rechazar(err instanceof Error ? err : new Error(String(err)));
		}
	});
}

/** ¿La app de escritorio de este equipo está instalada y abierta? */
export async function appEscritorioDisponible(): Promise<boolean> {
	try {
		const r = await enviar({ tipo: 'ping' });
		return r.ok === true;
	} catch {
		return false;
	}
}

/** `fetch` que entiende `URL_APP_ESCRITORIO`. */
export async function pedirAlServidor(url: string, init: { method: string; headers?: Record<string, string>; body?: string }): Promise<Response> {
	if (!esAppEscritorio(url)) return fetch(url, init);

	const ruta = url.slice(URL_APP_ESCRITORIO.length) || '/';
	const r = await enviar({
		tipo: 'http',
		metodo: init.method,
		ruta,
		headers: init.headers ?? {},
		cuerpo_b64: init.body !== undefined ? bytesABase64(new TextEncoder().encode(init.body)) : null
	});
	// El mismo `TypeError` que lanza `fetch` sin red: quien llama ya lo trata como "no se pudo contactar".
	if (r.error) throw new TypeError(mensajeDeError(r.error));
	const status = r.status ?? 500;
	const sinCuerpo = status === 204 || status === 304;
	const cuerpo = sinCuerpo || !r.cuerpo_b64 ? null : (base64ABytes(r.cuerpo_b64) as BufferSource);
	return new Response(cuerpo, { status, headers: r.headers ?? {} });
}
