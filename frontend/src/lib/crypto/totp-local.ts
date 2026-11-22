// Autor: Athan Espinoza

// F-38: desbloqueo rápido local con TOTP — "algo que tenés" en vez de
// "algo que sabés", opt-in por dispositivo, 100% client-side (nunca toca
// el backend para validar). Independiente del TOTP de login server-verified
// (F-14, `$lib/crypto/totp.ts`) — secreto propio, nunca el mismo código.
//
// Storage: `localStorage` directo, no vía `declararStore` — a propósito.
// `declararStore` con `clearOn: ['logout']` borraría esto en cada logout,
// pero el objetivo entero de F-38 es sobrevivir entre sesiones de login en
// el mismo dispositivo (revocable explícitamente, nunca implícito).
//
// Hallazgo de seguridad (auditoría 2026-08-12, H-01): esto guardaba el
// secreto TOTP crudo en `localStorage`, en el mismo objeto que el blob
// cifrado de la passphrase que ese secreto puede desenvolver — cualquiera
// con lectura de `localStorage` (backup de perfil robado, infostealer,
// dispositivo compartido) podía calcular un código válido offline (TOTP no
// es más que HMAC(secreto, tiempo), no hace falta ni siquiera adivinarlo) y
// recuperar la passphrase maestra sin el código real. El backoff de intentos
// nunca protegía nada porque no era parte de la operación criptográfica.
//
// Primer arreglo: envolver el secreto con una `CryptoKey` `extractable:false`
// en IndexedDB. No alcanzó (QA-08): Chromium y Firefox guardan el material
// de esa clave en los archivos del perfil, así que un backup o un
// infostealer se la lleva junto con el secreto y la passphrase.
//
// QA-08 (2026-11-22, pendiente #100): la clave que envuelve el secreto vive
// en el llavero del SO (Credential Manager / Secret Service, mismo almacén
// que F-50), fuera del perfil. Por eso F-38 existe sólo en el escritorio: en
// la web no hay nada fuera del perfil donde guardarla y se desactivó (lo que
// hubiera quedado de antes se borra al cargar). Sigue sin proteger contra JS
// activo en la página (XSS), mismo límite que el token de sesión.

import { cargarCrypto } from './wasm';
import { bytesABase64, base64ABytes } from './b64';
import { base32Codificar } from './base32';
import { obtenerClaveDeDispositivo, borrarClaveDeDispositivo } from './device-key';
import { guardarEnvolturaLlavero, recuperarEnvolturaLlavero, eliminarEnvolturaLlavero } from '$lib/tauri/llavero';
import { enModoEscritorio } from '$lib/tauri/conectar';

interface EstadoLocalTotp {
	/** 2 = clave en el llavero del SO; sin campo = clave vieja en IndexedDB. */
	version?: 2;
	/** Secreto TOTP cifrado con la clave del llavero, nunca en claro. */
	secretoCifradoB64: string;
	secretoIvB64: string;
	cipherB64: string;
	nonceB64: string;
}

interface EstadoBackoff {
	fallosConsecutivos: number;
	bloqueadoHastaMs: number | null;
}

function claveStorage(email: string): string {
	return `ellkan:totp-local:${email}`;
}

function claveBackoff(email: string): string {
	return `ellkan:totp-local-backoff:${email}`;
}

function claveDispositivo(email: string): string {
	return `totp-local:${email}`;
}

function aad(email: string): Uint8Array {
	return new TextEncoder().encode(`totp-local:${email}`);
}

function leerEstado(email: string): EstadoLocalTotp | null {
	const crudo = localStorage.getItem(claveStorage(email));
	if (!crudo) return null;
	try {
		return JSON.parse(crudo) as EstadoLocalTotp;
	} catch {
		return null;
	}
}

/** F-38 sólo existe en el escritorio (QA-08). */
export function disponible(): boolean {
	return enModoEscritorio();
}

export function estaActivo(email: string): boolean {
	return disponible() && leerEstado(email) !== null;
}

export async function desactivar(email: string): Promise<void> {
	localStorage.removeItem(claveStorage(email));
	localStorage.removeItem(claveBackoff(email));
	await borrarClaveDeDispositivo(claveDispositivo(email)).catch(() => {});
	await eliminarEnvolturaLlavero(claveDispositivo(email));
}

/**
 * Web (QA-08): borra lo que haya quedado de F-38 de cuando existía en la
 * web — el secreto envuelto en `localStorage` y la base de IndexedDB con la
 * clave que lo abría. Se llama una vez al arrancar.
 */
export async function limpiarRestosWeb(): Promise<void> {
	if (disponible()) return;
	const claves: string[] = [];
	for (let i = 0; i < localStorage.length; i++) {
		const k = localStorage.key(i);
		if (k?.startsWith('ellkan:totp-local')) claves.push(k);
	}
	claves.forEach((k) => localStorage.removeItem(k));
	if (typeof indexedDB !== 'undefined') indexedDB.deleteDatabase('ellkan-device-keys');
}

/**
 * Clave AES-GCM que envuelve el secreto TOTP. Sus bytes viven sólo en el
 * llavero del SO; acá se importa como `CryptoKey` no exportable y nunca se
 * persiste en el perfil. `crear` genera una nueva si no hay.
 */
async function claveDelLlavero(email: string, crear: boolean): Promise<CryptoKey | null> {
	let b64 = await recuperarEnvolturaLlavero(claveDispositivo(email));
	if (!b64 && crear) {
		const bytes = crypto.getRandomValues(new Uint8Array(32));
		b64 = bytesABase64(bytes);
		bytes.fill(0);
		await guardarEnvolturaLlavero(claveDispositivo(email), b64);
	}
	if (!b64) return null;
	const crudo = base64ABytes(b64);
	try {
		return await crypto.subtle.importKey('raw', crudo as BufferSource, 'AES-GCM', false, ['encrypt', 'decrypt']);
	} finally {
		crudo.fill(0);
	}
}

async function guardarEstado(email: string, clave: CryptoKey, secreto: Uint8Array, cipher: string, nonce: string) {
	const secretoIv = crypto.getRandomValues(new Uint8Array(12));
	const secretoCifrado = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: secretoIv }, clave, secreto as BufferSource);
	const estado: EstadoLocalTotp = {
		version: 2,
		secretoCifradoB64: bytesABase64(new Uint8Array(secretoCifrado)),
		secretoIvB64: bytesABase64(secretoIv),
		cipherB64: cipher,
		nonceB64: nonce
	};
	localStorage.setItem(claveStorage(email), JSON.stringify(estado));
}

/** Genera un secreto nuevo (nunca reusa el de F-14) y la URI para el QR de setup. */
export async function generarSetup(email: string): Promise<{ secreto: Uint8Array; otpauthUri: string }> {
	if (!disponible()) throw new Error('El desbloqueo rápido existe sólo en la app de escritorio.');
	const wasm = await cargarCrypto();
	const secreto = wasm.totp_generar_secreto();
	const secretoBase32 = base32Codificar(secreto);
	const otpauthUri = `otpauth://totp/Ellkan%20%28local%29:${encodeURIComponent(email)}?secret=${secretoBase32}&issuer=Ellkan%20%28local%29&algorithm=SHA1&digits=6&period=30`;
	return { secreto, otpauthUri };
}

/**
 * Confirma el setup: verifica el código contra el secreto recién generado
 * (mismo criterio que F-14 — no queda "activo" sin probar que el usuario
 * realmente lo agregó a una app real) y, si es válido, envuelve la
 * passphrase y persiste el estado en este dispositivo.
 */
export async function confirmarYActivar(
	email: string,
	secreto: Uint8Array,
	codigo: string,
	passphrase: string
): Promise<void> {
	const wasm = await cargarCrypto();
	const ahora = Math.floor(Date.now() / 1000);
	if (!wasm.totp_verificar(secreto, Number(codigo), BigInt(ahora))) {
		throw new Error('Código incorrecto.');
	}
	if (!disponible()) throw new Error('El desbloqueo rápido existe sólo en la app de escritorio.');
	const cifrado = wasm.totp_envolver_passphrase(secreto, passphrase, aad(email));

	const clave = await claveDelLlavero(email, true);
	if (!clave) throw new Error('No se pudo guardar la clave en el llavero del sistema.');
	await guardarEstado(email, clave, secreto, bytesABase64(cifrado.ciphertext), bytesABase64(cifrado.nonce));
	secreto.fill(0);
}

function leerBackoff(email: string): EstadoBackoff {
	const crudo = localStorage.getItem(claveBackoff(email));
	if (!crudo) return { fallosConsecutivos: 0, bloqueadoHastaMs: null };
	try {
		return JSON.parse(crudo) as EstadoBackoff;
	} catch {
		return { fallosConsecutivos: 0, bloqueadoHastaMs: null };
	}
}

function guardarBackoff(email: string, estado: EstadoBackoff): void {
	localStorage.setItem(claveBackoff(email), JSON.stringify(estado));
}

/**
 * Backoff tras intentos fallidos (mismo criterio que `ControlDeIntentos` de
 * `ellkan-crypto`, reimplementado acá en vez de exportar un objeto wasm
 * con estado — el estado de un módulo wasm no sobrevive un reload de
 * página de todos modos, así que `localStorage` es estrictamente mejor
 * para este propósito puntual, no una simplificación que pierda cobertura).
 * 3 fallos consecutivos → 30s de bloqueo, igual que el lado Rust.
 */
const INTENTOS_ANTES_DE_BLOQUEAR = 3;
const BLOQUEO_MS = 30_000;

/**
 * Desbloquea: verifica el código con backoff y, si es válido, devuelve la
 * passphrase reconstruida — el llamador sigue el mismo flujo que si el
 * usuario la hubiera tipeado (`iniciarSesion`, F-38 no se salta ningún paso
 * del login real, sólo evita que el usuario tenga que escribirla).
 */
export async function desbloquear(email: string, codigo: string): Promise<string> {
	const estado = disponible() ? leerEstado(email) : null;
	if (!estado) throw new Error('Desbloqueo rápido no está activo en este dispositivo.');

	const backoff = leerBackoff(email);
	const ahoraMs = Date.now();
	if (backoff.bloqueadoHastaMs && ahoraMs < backoff.bloqueadoHastaMs) {
		const segundos = Math.ceil((backoff.bloqueadoHastaMs - ahoraMs) / 1000);
		throw new Error(`Demasiados intentos fallidos — esperá ${segundos}s.`);
	}

	const wasm = await cargarCrypto();
	// Estado de antes de QA-08: la clave está en IndexedDB. Se abre una vez
	// con ella y, si el código es válido, se pasa al llavero (abajo).
	const viejo = estado.version !== 2;
	const clave = viejo ? await obtenerClaveDeDispositivo(claveDispositivo(email)) : await claveDelLlavero(email, false);
	if (!clave) {
		// El llavero ya no tiene la clave (borrada fuera de la app): sin ella
		// no hay forma de abrir el secreto; se desactiva y se usa la passphrase.
		await desactivar(email);
		throw new Error('El desbloqueo rápido se perdió en este equipo. Entrá con tu contraseña y activalo de nuevo.');
	}
	const secretoBuf = await crypto.subtle.decrypt(
		{ name: 'AES-GCM', iv: base64ABytes(estado.secretoIvB64) as BufferSource },
		clave,
		base64ABytes(estado.secretoCifradoB64) as BufferSource
	);
	const secreto = new Uint8Array(secretoBuf);
	const ahoraUnix = Math.floor(ahoraMs / 1000);
	const valido = wasm.totp_verificar(secreto, Number(codigo), BigInt(ahoraUnix));

	if (!valido) {
		const fallos = backoff.fallosConsecutivos + 1;
		guardarBackoff(email, {
			fallosConsecutivos: fallos,
			bloqueadoHastaMs: fallos >= INTENTOS_ANTES_DE_BLOQUEAR ? ahoraMs + BLOQUEO_MS : null
		});
		throw new Error('Código incorrecto.');
	}
	guardarBackoff(email, { fallosConsecutivos: 0, bloqueadoHastaMs: null });

	const passphrase = wasm.totp_desenvolver_passphrase(
		secreto,
		base64ABytes(estado.nonceB64),
		base64ABytes(estado.cipherB64),
		aad(email)
	);
	if (viejo) {
		const nueva = await claveDelLlavero(email, true);
		if (nueva) {
			await guardarEstado(email, nueva, secreto, estado.cipherB64, estado.nonceB64);
			await borrarClaveDeDispositivo(claveDispositivo(email));
		}
	}
	secreto.fill(0);
	return passphrase;
}
