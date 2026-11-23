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
import { sellarNuevo, type BlobClaveNueva } from './desbloqueo';
import { accountRecoveryApi, type ClaveOrg } from '$lib/api/accountRecovery';
import type { MaterialParaCustodio, SobreCustodio } from '$lib/api/admin';

/** El servidor nunca ve más que bytes opacos: concatena las dos privadas
 * antes de sellar contra la clave pública organizacional. Genérica pese al
 * nombre — sella contra CUALQUIER clave pública X25519, no sólo la de la
 * org; `recovery_kit` la reusa tal cual bajo el alias `sellarMaterialParaKit`
 * para sellar contra la pública del kit en vez de la de la org. */
export async function sellarMaterialParaOrg(orgPublicKeyB64: string, claves: ClavesDesbloqueadas): Promise<string> {
	const wasm = await cargarCrypto();
	const material = new Uint8Array(64);
	material.set(claves.x25519Private, 0);
	material.set(claves.ed25519Private, 32);
	try {
		return bytesABase64(wasm.sellar_para(base64ABytes(orgPublicKeyB64), material));
	} finally {
		material.fill(0);
	}
}

/** F-16: habilita (o re-sella, tras una rotación) el escrow propio contra la
 * clave organizacional vigente. QA-09: el servidor rechaza (409) un sellado
 * contra una clave que ya no es la vigente. */
export async function enrolarConClaveVigente(claves: ClavesDesbloqueadas, org?: ClaveOrg): Promise<void> {
	const clave = org ?? (await accountRecoveryApi.orgPublicKey());
	const sellado = await sellarMaterialParaOrg(clave.public_key_x25519_b64, claves);
	await accountRecoveryApi.enrolar(sellado, clave.id);
}

/** QA-09: genera en este navegador el par de la clave organizacional y
 * sella la privada para cada custodio. La privada nunca sale de acá sin
 * sellar; el servidor sólo recibe la pública y las copias selladas. */
export async function generarClaveOrg(
	custodios: { user_id: string; public_key_x25519_b64: string }[]
): Promise<{ publicaB64: string; sobres: SobreCustodio[] }> {
	const wasm = await cargarCrypto();
	const identidad = wasm.generar_identidad();
	const privada = identidad.x25519_private;
	const descartada = identidad.ed25519_private;
	try {
		const sobres = custodios.map((c) => ({
			admin_id: c.user_id,
			sealed_private_key_b64: bytesABase64(wasm.sellar_para(base64ABytes(c.public_key_x25519_b64), privada))
		}));
		return { publicaB64: bytesABase64(identidad.x25519_public), sobres };
	} finally {
		privada.fill(0);
		descartada.fill(0);
		identidad.free();
	}
}

/** QA-09: un custodio abre su copia de la clave vigente y se la sella a
 * otro admin. */
export async function sellarParaCustodio(miSobreB64: string, miX25519Private: Uint8Array, publicaCustodioB64: string): Promise<string> {
	const wasm = await cargarCrypto();
	const privadaOrg = wasm.abrir_sellado(miX25519Private, base64ABytes(miSobreB64));
	try {
		return bytesABase64(wasm.sellar_para(base64ABytes(publicaCustodioB64), privadaOrg));
	} finally {
		privadaOrg.fill(0);
	}
}

/** QA-09: re-sella el escrow de una solicitud aprobada para la clave
 * efímera del solicitante — lo que antes hacía el servidor. */
export async function resellarComoCustodio(m: MaterialParaCustodio, miX25519Private: Uint8Array): Promise<string> {
	const wasm = await cargarCrypto();
	const privadaOrg = wasm.abrir_sellado(miX25519Private, base64ABytes(m.envelope_b64));
	let material: Uint8Array | undefined;
	try {
		material = wasm.abrir_sellado(privadaOrg, base64ABytes(m.sealed_private_key_for_org_b64));
		return bytesABase64(wasm.sellar_para(base64ABytes(m.requester_public_key_x25519_b64), material));
	} finally {
		privadaOrg.fill(0);
		material?.fill(0);
	}
}

export { sellarMaterialParaOrg as sellarMaterialParaKit };

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

/** Modo escritorio (punto 8): firma un challenge con la clave Ed25519 del
 * material recuperado del kit (bytes 32..64, ver `sellarMaterialParaOrg`).
 * Es la prueba de que quien recupera tiene el kit, sin correo de por medio —
 * el backend la verifica contra la pública que ya guardó al registrarse. */
export async function firmarChallengeConMaterial(material: Uint8Array, nonce: Uint8Array): Promise<string> {
	const wasm = await cargarCrypto();
	return bytesABase64(wasm.firmar(material.slice(32, 64), nonce));
}

// QA-03: el blob nuevo, la prueba de posesión y el sellado viven en
// `desbloqueo.ts` (llevan parámetros de Argon2id y `auth_key`); se
// re-exportan acá para los llamadores de siempre.
export { pruebaDePosesion, type BlobClaveNueva, type PruebaDePosesion } from './desbloqueo';

/** Fija una passphrase nueva sobre el material recuperado — mismo sellado
 * que `identity.ts::cambiarPassphrase` usa para el cambio voluntario. */
export async function reSellarConNuevaPassphrase(email: string, passphraseNueva: string, material: Uint8Array): Promise<BlobClaveNueva> {
	return sellarNuevo(passphraseNueva, material.slice(0, 32), material.slice(32, 64), email);
}
