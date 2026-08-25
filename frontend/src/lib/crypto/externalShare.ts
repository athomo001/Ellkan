// Autor: Athan Espinoza

// F-26: lógica de dominio del External Secure Share, lado cliente. El
// servidor sólo guarda un blob `ciphertext` opaco (una única columna, sin
// nonce separado — ver `spec/02-modelo-de-datos.md` §6), así que acá se fija
// el formato de ese blob: `nonce (24 bytes) || ciphertext`. La clave K nunca
// se manda al servidor — vive sólo en el fragmento de la URL (`#...`), que
// el navegador nunca envía en ninguna request.

import { cargarCrypto } from './wasm';
import { base64ABytes, bytesABase64, base64UrlABytes, bytesABase64Url } from './b64';

/** AAD fijo, no atado a un id — a diferencia del AAD de un recurso
 * (`resource_id || created_by`), el `id` del share no existe todavía en el
 * momento en que el creador cifra (lo asigna el servidor recién al
 * `POST`). Cada share usa una clave K de un solo uso generada al azar, así
 * que un contexto fijo no reintroduce el riesgo que el AAD por-id evita en
 * el resto de la app (reuso de la misma clave entre objetos distintos). */
const AAD_EXTERNAL_SHARE = new TextEncoder().encode('ellkan:v1:external-share');

function empaquetarCifrado(nonce: Uint8Array, ciphertext: Uint8Array): Uint8Array {
	const blob = new Uint8Array(nonce.length + ciphertext.length);
	blob.set(nonce, 0);
	blob.set(ciphertext, nonce.length);
	return blob;
}

function desempaquetarCifrado(blob: Uint8Array): { nonce: Uint8Array; ciphertext: Uint8Array } {
	return { nonce: blob.slice(0, 24), ciphertext: blob.slice(24) };
}

/** Genera K (clave simétrica de un solo uso) y cifra el contenido — usado
 * al crear un share. Devuelve el blob listo para `ciphertext_b64` y la
 * clave K en base64url, lista para ir en el fragmento de la URL. Si se pasa
 * `passphrase` (capa opcional F-26, exigible por política de organización),
 * la clave real de cifrado combina K con esa passphrase (mismo camino
 * simétrico que `combinar_clave_de_share_con_passphrase` usa al descifrar),
 * y también devuelve el salt que el destinatario va a necesitar. */
export async function cifrarContenidoDeShare(
	contenido: string,
	passphrase?: string
): Promise<{ ciphertextB64: string; claveFragmentoB64Url: string; passwordSaltB64?: string }> {
	const wasm = await cargarCrypto();
	const claveFragmento = wasm.generar_dek();

	let claveReal = claveFragmento;
	let passwordSaltB64: string | undefined;
	if (passphrase) {
		const salt = crypto.getRandomValues(new Uint8Array(16));
		claveReal = wasm.combinar_clave_de_share_con_passphrase(claveFragmento, passphrase, salt);
		passwordSaltB64 = bytesABase64(salt);
	}

	const cifrado = wasm.cifrar_aead(claveReal, new TextEncoder().encode(contenido), AAD_EXTERNAL_SHARE);
	const blob = empaquetarCifrado(cifrado.nonce, cifrado.ciphertext);
	return { ciphertextB64: bytesABase64(blob), claveFragmentoB64Url: bytesABase64Url(claveFragmento), passwordSaltB64 };
}

/** Descifra el contenido de un share ya obtenido de `GET
 * /external-shares/{id}` — `claveFragmento` viene de `location.hash`, nunca
 * del servidor. Si `password_protected`, primero combina esa clave con la
 * passphrase del destinatario (Argon2id + HKDF, 100% en Rust/wasm, nunca
 * reimplementado en TS). Lanza si la clave/passphrase es incorrecta o el
 * blob está corrupto — el llamador decide cómo mostrarlo. */
export async function descifrarContenidoDeShare(
	ciphertextB64: string,
	claveFragmentoB64Url: string,
	opciones: { passwordProtected: boolean; passwordSaltB64?: string; passphrase?: string }
): Promise<string> {
	const wasm = await cargarCrypto();
	const claveFragmento = base64UrlABytes(claveFragmentoB64Url);

	let clave = claveFragmento;
	if (opciones.passwordProtected) {
		if (!opciones.passwordSaltB64 || !opciones.passphrase) {
			throw new Error('este share requiere una passphrase');
		}
		clave = wasm.combinar_clave_de_share_con_passphrase(
			claveFragmento,
			opciones.passphrase,
			base64ABytes(opciones.passwordSaltB64)
		);
	}

	const { nonce, ciphertext } = desempaquetarCifrado(base64ABytes(ciphertextB64));
	const plano = wasm.descifrar_aead(clave, nonce, ciphertext, AAD_EXTERNAL_SHARE);
	return new TextDecoder().decode(plano);
}

/** Clave del fragmento de la URL actual (`#...`) — nunca leída de
 * `location.search`/query string, que sí viaja al servidor. */
export function claveFragmentoDeUrl(): string | null {
	if (typeof location === 'undefined') return null;
	const hash = location.hash.startsWith('#') ? location.hash.slice(1) : location.hash;
	return hash.length > 0 ? hash : null;
}

/** Segunda forma de compartir externo (2026-08-24, pedido explícito): un
 * `.7z` con AES-256 + header cifrado, generado 100% client-side — a
 * diferencia de `cifrarContenidoDeShare`, esto no toca el servidor para
 * nada, ni siquiera como blob opaco, así que no depende de que la instancia
 * sea alcanzable desde afuera. `passwordArchivo` la elige quien comparte y
 * se la pasa al destinatario por otro canal (nunca la misma passphrase que
 * la cuenta de Ellkan). `contenido` ya viene armado por el llamador (un
 * recurso o varios, ver `bloqueDeRecurso` en la página del Vault) — esta
 * función sólo empaqueta y cifra, no decide qué campos incluir.*/
export async function crearArchivoCompartido(contenido: string, passwordArchivo: string): Promise<Uint8Array> {
	const wasm = await cargarCrypto();
	return wasm.crear_archivo_7z_cifrado('ellkan.txt', new TextEncoder().encode(contenido), passwordArchivo);
}
