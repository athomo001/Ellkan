// Autor: Athan Espinoza

// Revocación remota (docs/revocacion-remota.md): si el admin del servidor
// vinculado bloquea o borra la cuenta, la app de escritorio borra su bóveda
// local completa. Es irreversible, así que NUNCA se borra por inferencia (un
// 401, un servidor caído o restaurado de un backup viejo): sólo ante un aviso
// firmado con la clave del servidor que la app fijó al vincularse
// (`VinculacionServidor.serverKeyB64`), dirigido a esta cuenta y emitido
// después de esa fijación. Si algo no cuadra, no se borra nada.
//
// El aviso llega por dos caminos: en vivo (`event: cuenta_revocada` en
// `avisosServidor.ts`) o, si la app estaba sin red, preguntando con
// `POST /auth/estado-cuenta` cuando la re-autenticación falla.

import { get, writable } from 'svelte/store';
import { api } from '$lib/api/client';
import { cargarCrypto } from '../crypto/wasm';
import { base64ABytes, bytesABase64 } from '../crypto/b64';
import { clavesDesbloqueadas, sesion, type ClavesDesbloqueadas } from '$lib/state/session';
import { enModoEscritorio } from '$lib/tauri/conectar';
import { obtenerVinculacion, type VinculacionServidor } from './vinculacion';
import { clienteRemoto } from './remoteClient';

export interface AvisoFirmado {
	aviso: string;
	firma_b64: string;
}

interface CuerpoAviso {
	tipo: string;
	user_id: string;
	email?: string;
	motivo: 'deactivated' | 'purged';
	emitido_en: string;
}

/** Cuenta revocada: el layout tapa todo con la pantalla final. */
export const cuentaRevocada = writable<{ servidor: string; motivo: CuerpoAviso['motivo'] } | null>(null);

/** Tolerancia de reloj entre la app y el servidor. */
const MARGEN_MS = 10 * 60_000;

/** Ed25519 con WebCrypto. Sin soporte (o cualquier error) → `false`: no se borra. */
async function firmaValida(publicaB64: string, mensaje: string, firmaB64: string): Promise<boolean> {
	try {
		const clave = await crypto.subtle.importKey('raw', base64ABytes(publicaB64) as BufferSource, { name: 'Ed25519' }, false, ['verify']);
		return await crypto.subtle.verify({ name: 'Ed25519' }, clave, base64ABytes(firmaB64) as BufferSource, new TextEncoder().encode(mensaje));
	} catch {
		return false;
	}
}

/** `null` si el aviso no es válido para esta vinculación (y por qué, en consola). */
export async function verificarAviso(v: VinculacionServidor, firmado: AvisoFirmado): Promise<CuerpoAviso | null> {
	const rechazar = (motivo: string) => {
		console.warn(`aviso de revocación ignorado: ${motivo}`);
		return null;
	};
	if (!v.serverKeyB64 || !v.userId || !v.fijadaEn) return rechazar('la clave del servidor todavía no estaba fijada');
	if (!(await firmaValida(v.serverKeyB64, firmado.aviso, firmado.firma_b64))) return rechazar('firma inválida');

	let cuerpo: CuerpoAviso;
	try {
		cuerpo = JSON.parse(firmado.aviso) as CuerpoAviso;
	} catch {
		return rechazar('formato inválido');
	}
	if (cuerpo.tipo !== 'cuenta_revocada') return rechazar('tipo desconocido');
	if (cuerpo.user_id !== v.userId) return rechazar('es para otra cuenta');
	if (cuerpo.email && cuerpo.email.toLowerCase() !== v.email.toLowerCase()) return rechazar('es para otro correo');
	const emitido = Date.parse(cuerpo.emitido_en);
	// Un aviso anterior a la vinculación (repetido por alguien que lo guardó
	// de una revocación vieja) no vale.
	if (!Number.isFinite(emitido) || emitido < Date.parse(v.fijadaEn) - MARGEN_MS) return rechazar('es anterior a la vinculación');
	return cuerpo;
}

let borrando = false;

/** Verifica el aviso y, si vale, borra la bóveda local. */
export async function procesarAvisoRevocacion(firmado: AvisoFirmado): Promise<void> {
	if (!enModoEscritorio() || borrando) return;
	const email = get(sesion).email;
	const v = email ? obtenerVinculacion(email) : null;
	if (!v) return;
	const cuerpo = await verificarAviso(v, firmado);
	if (!cuerpo) return;
	await borrarBovedaLocal(v, cuerpo.motivo);
}

async function borrarBovedaLocal(v: VinculacionServidor, motivo: CuerpoAviso['motivo']): Promise<void> {
	borrando = true;
	// Primero se tapa todo y se descartan las claves: desde acá no se ve nada más.
	cuentaRevocada.set({ servidor: v.serverUrl, motivo });
	clavesDesbloqueadas.set(null);

	// El backend local corta el acceso, cierra la base y la borra.
	await api.post('/desktop/borrado-remoto', { servidor: v.serverUrl }).catch((err) => {
		console.error('no se pudo pedir el borrado de la bóveda local', err);
	});
	try {
		const { invoke } = await import('@tauri-apps/api/core');
		await invoke('limpiar_restos_revocacion');
	} catch {
		/* llavero / desktop.json: se reintenta al arrancar si quedó la marca */
	}
	// Lo que guardó la ventana: vinculación, cursor, desbloqueo rápido, preferencias.
	try {
		localStorage.clear();
		sessionStorage.clear();
	} catch {
		/* sin almacenamiento accesible */
	}
}

/** Para no preguntar en cada intento fallido de sync. */
const ESPERA_ENTRE_CONSULTAS_MS = 60_000;
let ultimaConsulta = 0;

/**
 * Pregunta al servidor por el estado de la cuenta, firmando la pregunta con
 * la clave Ed25519 de la cuenta (el servidor sólo le contesta algo útil al
 * dueño de las claves). Se llama cuando la re-autenticación falla.
 */
export async function comprobarEstadoCuenta(v: VinculacionServidor, claves: ClavesDesbloqueadas): Promise<void> {
	if (!enModoEscritorio() || Date.now() - ultimaConsulta < ESPERA_ENTRE_CONSULTAS_MS) return;
	ultimaConsulta = Date.now();
	const wasm = await cargarCrypto();
	const publicaB64 = bytesABase64(claves.ed25519Public);
	const emitidoEn = new Date().toISOString();
	const mensaje = `ellkan:estado-cuenta:v1\n${v.email}\n${publicaB64}\n${emitidoEn}`;
	const firma = wasm.firmar(claves.ed25519Private, new TextEncoder().encode(mensaje));
	const respuesta = await clienteRemoto(v.serverUrl, null).post<{ estado: string; aviso?: AvisoFirmado }>('/auth/estado-cuenta', {
		email: v.email,
		public_key_ed25519_b64: publicaB64,
		emitido_en: emitidoEn,
		firma_b64: bytesABase64(firma)
	});
	if (respuesta.estado === 'revocada' && respuesta.aviso) await procesarAvisoRevocacion(respuesta.aviso);
}
