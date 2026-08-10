// Autor: Athan Espinoza

// F-16 (frontend): mismo patrón de `sellar_para`/`abrir_sellado` que ya usan
// `recursos.ts`/`carpetas.ts` para sellado asimétrico — acá el "secreto"
// sellado es el material de clave privada del propio usuario (64 bytes:
// x25519_private + ed25519_private concatenados, mismo formato interno que
// `wasm.sellar_clave_privada` ya arma para `identity.ts::cambiarPassphrase`),
// nunca una DEK de recurso. Cero criptografía nueva del lado WASM.

import { cargarCrypto } from './wasm';
import { bytesABase64, base64ABytes } from './b64';
import type { ClavesDesbloqueadas } from '$lib/state/session';

/** El servidor nunca ve más que bytes opacos: concatena las dos privadas
 * antes de sellar contra la clave pública organizacional. */
export async function sellarMaterialParaOrg(orgPublicKeyB64: string, claves: ClavesDesbloqueadas): Promise<string> {
	const wasm = await cargarCrypto();
	const material = new Uint8Array(64);
	material.set(claves.x25519Private, 0);
	material.set(claves.ed25519Private, 32);
	const sellado = wasm.sellar_para(base64ABytes(orgPublicKeyB64), material);
	return bytesABase64(sellado);
}

export interface ClaveEfimera {
	privada: Uint8Array;
	publicaB64: string;
}

/** Par X25519 de un solo uso para una solicitud de recuperación puntual —
 * reusa `generar_identidad()` (ya expuesto al WASM) y descarta el par
 * Ed25519 sobrante: no hace falta un binding WASM nuevo sólo para esto. */
export async function generarClaveEfimera(): Promise<ClaveEfimera> {
	const wasm = await cargarCrypto();
	const identidad = wasm.generar_identidad();
	return { privada: identidad.x25519_private, publicaB64: bytesABase64(identidad.x25519_public) };
}

/** Desella el material del escrow con la privada de la clave efímera —
 * produce los mismos 64 bytes que se sellaron al enrolarse. */
export async function desellarMaterialDelEscrow(efimeraPrivada: Uint8Array, selladoB64: string): Promise<Uint8Array> {
	const wasm = await cargarCrypto();
	return wasm.abrir_sellado(efimeraPrivada, base64ABytes(selladoB64));
}

export interface BlobClaveNueva {
	blobB64: string;
	nonceB64: string;
	saltB64: string;
}

/** Fija una passphrase nueva sobre el material recuperado — mismo wrapper
 * que `identity.ts::cambiarPassphrase` usa para el cambio voluntario. */
export async function reSellarConNuevaPassphrase(
	email: string,
	passphraseNueva: string,
	material: Uint8Array
): Promise<BlobClaveNueva> {
	const wasm = await cargarCrypto();
	const salt = wasm.generar_salt_kdf();
	const blob = wasm.sellar_clave_privada(
		passphraseNueva,
		salt,
		material.slice(0, 32),
		material.slice(32, 64),
		new TextEncoder().encode(email)
	);
	return { blobB64: bytesABase64(blob.ciphertext), nonceB64: bytesABase64(blob.nonce), saltB64: bytesABase64(salt) };
}
