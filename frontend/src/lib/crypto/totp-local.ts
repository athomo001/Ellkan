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

import { cargarCrypto } from './wasm';
import { bytesABase64, base64ABytes } from './b64';
import { base32Codificar } from './base32';

interface EstadoLocalTotp {
	secretoB64: string;
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

export function estaActivo(email: string): boolean {
	return leerEstado(email) !== null;
}

export function desactivar(email: string): void {
	localStorage.removeItem(claveStorage(email));
	localStorage.removeItem(claveBackoff(email));
}

/** Genera un secreto nuevo (nunca reusa el de F-14) y la URI para el QR de setup. */
export async function generarSetup(email: string): Promise<{ secreto: Uint8Array; otpauthUri: string }> {
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
	const cifrado = wasm.totp_envolver_passphrase(secreto, passphrase, aad(email));
	const estado: EstadoLocalTotp = {
		secretoB64: bytesABase64(secreto),
		cipherB64: bytesABase64(cifrado.ciphertext),
		nonceB64: bytesABase64(cifrado.nonce)
	};
	localStorage.setItem(claveStorage(email), JSON.stringify(estado));
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
	const estado = leerEstado(email);
	if (!estado) throw new Error('Desbloqueo rápido no está activo en este dispositivo.');

	const backoff = leerBackoff(email);
	const ahoraMs = Date.now();
	if (backoff.bloqueadoHastaMs && ahoraMs < backoff.bloqueadoHastaMs) {
		const segundos = Math.ceil((backoff.bloqueadoHastaMs - ahoraMs) / 1000);
		throw new Error(`Demasiados intentos fallidos — esperá ${segundos}s.`);
	}

	const wasm = await cargarCrypto();
	const secreto = base64ABytes(estado.secretoB64);
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

	return wasm.totp_desenvolver_passphrase(
		secreto,
		base64ABytes(estado.nonceB64),
		base64ABytes(estado.cipherB64),
		aad(email)
	);
}
