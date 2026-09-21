// Autor: Athan Espinoza

// F-50: desbloqueo rápido vía el llavero/biometría del SO (Windows
// Credential Manager / Secret Service en Linux) — mismo espíritu que F-38
// (`totp-local.ts`): la passphrase real nunca se manda al servidor para
// esto, sólo se envuelve localmente y se desenvuelve para seguir el login
// normal sin volver a escribirla. A diferencia de F-38 (clave derivada de
// un secreto TOTP que el usuario también posee), acá la clave de
// envoltura es un DEK aleatorio que NUNCA sale de la máquina: sólo vive en
// el almacén nativo de credenciales del SO (`$lib/tauri/llavero.ts`,
// comandos Tauri `guardar/recuperar/eliminar_envoltura_llavero`, criterio
// H-01 — nunca la passphrase/clave privada en claro en ese almacén).
//
// Sólo tiene sentido en modo escritorio (Tauri) — en la web no hay
// llavero del SO al que preguntarle; `enModoEscritorio()` gatea cada
// función acá, mismo criterio que `llavero.ts`.

import { cargarCrypto } from './wasm';
import { bytesABase64, base64ABytes } from './b64';
import { guardarEnvolturaLlavero, recuperarEnvolturaLlavero, eliminarEnvolturaLlavero } from '$lib/tauri/llavero';
import { enModoEscritorio } from '$lib/tauri/conectar';

interface BlobEnvuelto {
	cipherB64: string;
	nonceB64: string;
}

function claveStorage(email: string): string {
	return `ellkan:llavero-local:${email}`;
}

function aad(email: string): Uint8Array {
	return new TextEncoder().encode(`llavero-local:${email}`);
}

function leerBlob(email: string): BlobEnvuelto | null {
	const crudo = localStorage.getItem(claveStorage(email));
	if (!crudo) return null;
	try {
		return JSON.parse(crudo) as BlobEnvuelto;
	} catch {
		return null;
	}
}

/** `true` si ya hay una passphrase envuelta guardada localmente para este
 * email en este dispositivo — no confirma que el llavero del SO todavía
 * tenga la clave (eso recién se descubre al intentar `desbloquear`). */
export function estaActivo(email: string): boolean {
	return enModoEscritorio() && leerBlob(email) !== null;
}

/**
 * Genera una clave de envoltura aleatoria nueva, envuelve la passphrase ya
 * verificada (el caller la confirma con `verificarPassphrase` antes de
 * llamar acá, mismo criterio que F-38) y persiste: la clave va al llavero
 * nativo del SO, el blob cifrado a `localStorage` — nunca la clave junto
 * al blob que abre, separación física entre "la llave" y "la puerta"
 * (mismo espíritu que `device-key.ts`).
 */
export async function activar(email: string, passphrase: string): Promise<void> {
	const wasm = await cargarCrypto();
	const clave = wasm.generar_dek();
	const cifrado = wasm.cifrar_aead(clave, new TextEncoder().encode(passphrase), aad(email));

	await guardarEnvolturaLlavero(email, bytesABase64(clave));
	const blob: BlobEnvuelto = { cipherB64: bytesABase64(cifrado.ciphertext), nonceB64: bytesABase64(cifrado.nonce) };
	localStorage.setItem(claveStorage(email), JSON.stringify(blob));
}

export async function desactivar(email: string): Promise<void> {
	localStorage.removeItem(claveStorage(email));
	await eliminarEnvolturaLlavero(email);
}

/**
 * Recupera la clave del llavero del SO y desenvuelve la passphrase — el
 * llamador sigue el mismo flujo que si el usuario la hubiera tipeado
 * (`iniciarSesion`), mismo criterio que `totp-local.ts::desbloquear`.
 * `null` si el llavero no tiene la clave (revocada afuera de la app,
 * servicio de llavero no disponible, etc.) — degradación explícita, el
 * caller cae a pedir la passphrase normal, nunca falla en silencio.
 */
export async function desbloquear(email: string): Promise<string | null> {
	const blob = leerBlob(email);
	if (!blob) return null;

	const claveB64 = await recuperarEnvolturaLlavero(email);
	if (!claveB64) return null;

	const wasm = await cargarCrypto();
	const bytes = wasm.descifrar_aead(base64ABytes(claveB64), base64ABytes(blob.nonceB64), base64ABytes(blob.cipherB64), aad(email));
	return new TextDecoder().decode(bytes);
}
