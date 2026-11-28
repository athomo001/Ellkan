// Autor: Athan Espinoza

// F-36 (pendiente #131): el material del acceso de emergencia es el mismo
// que el de F-16 (las dos claves privadas del titular, 64 bytes), sellado
// para la clave pública X25519 del contacto en vez de la de la organización.
//
// 04-seguridad §"key escrow": el servidor podría entregar una clave pública
// falsa para quedarse con el material. Por eso la pantalla muestra la huella
// de la clave del contacto antes de sellar, para compararla con la que el
// contacto ve en su propia cuenta («Mis claves»).

import { api } from '#lib/api/client';
import { emergenciaApi, type PersonaEmergencia } from '#lib/api/emergencia';
import { cargarCrypto } from './wasm';
import { aadDeRecurso, secretoDesdeJson, type SecretoAbierto, type SecretoJson } from './recursos';
import { base64ABytes, bytesABase64 } from './b64';
import { camposDelBlob, pruebaDePosesion, sellarNuevo } from './desbloqueo';
import { sellarMaterialParaOrg } from './accountRecovery';
import type { ClavesDesbloqueadas } from '#lib/state/session';

export interface ContactoConClave {
	user_id: string;
	public_key_x25519_b64: string;
	/** Huella de la clave pública, mismo formato que «Mis claves». */
	huella: string;
}

/** Huella de una clave pública con el formato de «Mis claves»
 * (`settings/keys`): SHA-256 en base64, primeros 16 caracteres. Tiene que
 * coincidir exacto para que el contacto pueda compararla. */
export async function huellaDeClave(publicaB64: string): Promise<string> {
	const digest = await crypto.subtle.digest('SHA-256', new Uint8Array(base64ABytes(publicaB64)));
	return bytesABase64(new Uint8Array(digest)).slice(0, 16);
}

export async function buscarContacto(email: string): Promise<ContactoConClave> {
	const r = await api.get<{ user_id: string; public_key_x25519_b64: string }>(`/users/${encodeURIComponent(email.trim())}/public-key`);
	return { ...r, huella: await huellaDeClave(r.public_key_x25519_b64) };
}

export function sellarMaterialParaContacto(contacto: ContactoConClave, claves: ClavesDesbloqueadas): Promise<string> {
	return sellarMaterialParaOrg(contacto.public_key_x25519_b64, claves);
}

/** F-36 (#134): un recurso del titular ya abierto, para la vista de sólo
 * lectura del contacto. */
export interface RecursoDelTitular {
	id: string;
	tipo: string;
	nombre: string;
	usuario: string;
	uri: string;
	secreto: SecretoAbierto;
}

export interface BovedaDelTitular {
	titular: PersonaEmergencia;
	nivel: 'view' | 'takeover';
	recursos: RecursoDelTitular[];
	/** Los que no se pudieron abrir (sobre dañado, clave rotada después de
	 * designar al contacto). */
	sinAbrir: number;
}

/**
 * Abre en este navegador la bóveda del titular: el material (sus privadas)
 * se abre con la X25519 propia, y con la X25519 del titular cada sobre. Nada
 * de esto vuelve al servidor; las privadas del titular se ponen en cero al
 * terminar. El servidor audita la lectura.
 */
export async function abrirBovedaDelTitular(id: string, claves: ClavesDesbloqueadas): Promise<BovedaDelTitular> {
	const wasm = await cargarCrypto();
	const cruda = await emergenciaApi.boveda(id);
	const material = wasm.abrir_sellado(claves.x25519Private, base64ABytes(cruda.sealed_material_b64));
	const privadaTitular = material.slice(0, 32);
	material.fill(0);
	const recursos: RecursoDelTitular[] = [];
	let sinAbrir = 0;
	try {
		for (const r of cruda.resources) {
			if (!r.created_by) {
				sinAbrir++;
				continue;
			}
			let dek: Uint8Array | undefined;
			let claveMetadata: Uint8Array | undefined;
			try {
				dek = wasm.abrir_sellado(privadaTitular, base64ABytes(r.sealed_dek_b64));
				claveMetadata =
					r.metadata_key_type === 'shared_key' && r.metadata_sealed_key_b64
						? wasm.abrir_sellado(privadaTitular, base64ABytes(r.metadata_sealed_key_b64))
						: dek;
				const aad = aadDeRecurso(r.id, r.created_by);
				const metadata = JSON.parse(
					new TextDecoder().decode(
						wasm.descifrar_aead(claveMetadata, base64ABytes(r.metadata_nonce_b64), base64ABytes(r.metadata_ciphertext_b64), aad)
					)
				) as { name?: string; username?: string; uri?: string };
				const secreto: SecretoJson = JSON.parse(
					new TextDecoder().decode(
						wasm.descifrar_aead(dek, base64ABytes(r.secret_nonce_b64), base64ABytes(r.secret_ciphertext_b64), aad)
					)
				);
				recursos.push({
					id: r.id,
					tipo: r.resource_type_slug,
					nombre: metadata.name ?? '',
					usuario: metadata.username ?? '',
					uri: metadata.uri ?? '',
					secreto: secretoDesdeJson(secreto)
				});
			} catch (err) {
				console.error(`[emergencia] no se pudo abrir el recurso ${r.id}`, err);
				sinAbrir++;
			} finally {
				if (claveMetadata && claveMetadata !== dek) claveMetadata.fill(0);
				dek?.fill(0);
			}
		}
	} finally {
		privadaTitular.fill(0);
	}
	recursos.sort((a, b) => a.nombre.localeCompare(b.nombre));
	return { titular: cruda.granter, nivel: cruda.access_level, recursos, sinAbrir };
}

/**
 * F-36 (#134), nivel `takeover`: le fija al titular una passphrase nueva.
 * Mismo procedimiento que `cambiarPassphrase` (re-sellar sus privadas con la
 * passphrase nueva, AAD = su correo, y firmar el reemplazo con su Ed25519
 * sobre un desafío emitido para su cuenta), con las privadas que vienen en
 * el material. El servidor cierra todas las sesiones del titular y lo audita.
 */
export async function tomarControlDeLaCuenta(id: string, passphraseNueva: string, claves: ClavesDesbloqueadas): Promise<void> {
	const wasm = await cargarCrypto();
	const acceso = (await emergenciaApi.listar()).find((a) => a.id === id);
	if (!acceso?.sealed_material_b64) throw new Error('acceso no concedido');
	const material = wasm.abrir_sellado(claves.x25519Private, base64ABytes(acceso.sealed_material_b64));
	const x25519 = material.slice(0, 32);
	const ed25519 = material.slice(32, 64);
	material.fill(0);
	try {
		const email = acceso.granter.email;
		const blob = await sellarNuevo(passphraseNueva, x25519, ed25519, email);
		const prueba = await pruebaDePosesion(api.post, email, ed25519, blob);
		await emergenciaApi.takeover(id, { ...camposDelBlob(blob), ...prueba });
	} finally {
		x25519.fill(0);
		ed25519.fill(0);
	}
}
