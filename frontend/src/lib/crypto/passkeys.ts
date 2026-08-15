// Autor: Athan Espinoza

// F-03: ceremonia WebAuthn estándar vía las APIs nativas de nivel 3
// (`PublicKeyCredential.parseCreationOptionsFromJSON`/
// `parseRequestOptionsFromJSON`/`credential.toJSON()`) — el formato JSON de
// esas APIs coincide exactamente con el que produce `webauthn-rs-proto`
// (mismo esquema `Base64URLString` sin padding, camelCase, `id`/`rawId`/
// `response`/`type`/`clientExtensionResults`), así que no hace falta
// convertir ArrayBuffer↔base64url a mano.
//
// PRF (WebAuthn nivel 3): `webauthn-rs` 0.6.1-dev no tiene tipos para esta
// extensión (confirmado leyendo `webauthn-rs-proto`), así que el input/output
// se maneja acá directo sobre el objeto nativo del navegador, sin pasar por
// el JSON que arma el backend — el servidor nunca necesita saber que existe,
// sólo guarda/devuelve el blob opaco ya envuelto (`prf_wrapped_private_key_b64`).
// El salt de evaluación es fijo y público (no es secreto, sólo separa el
// dominio de esta app del resto de usos de PRF del mismo autenticador) —
// tiene que ser idéntico en registro y en cada login, por eso está hardcodeado
// acá en vez de generado al azar.

import { cargarCrypto } from './wasm';
import { bytesABase64, base64ABytes } from './b64';
import { desbloquearConPassphrase } from './identity';
import { api } from '$lib/api/client';
import type { ClavesDesbloqueadas } from '$lib/state/session';

const PRF_EVAL_SALT = new Uint8Array([
	0x65, 0x6c, 0x6c, 0x6b, 0x61, 0x6e, 0x3a, 0x76, 0x31, 0x3a, 0x77, 0x65, 0x62, 0x61, 0x75, 0x74, 0x68, 0x6e, 0x2d,
	0x70, 0x72, 0x66, 0x2d, 0x73, 0x61, 0x6c, 0x74, 0x00, 0x00, 0x00, 0x00, 0x00
]);

function aadPrf(email: string): Uint8Array {
	return new TextEncoder().encode(`webauthn-prf:${email}`);
}

interface PrfExtensionInputs {
	eval: { first: BufferSource };
}
interface PrfExtensionOutputs {
	enabled?: boolean;
	results?: { first?: ArrayBuffer };
}

function requerirWebauthnJson(): void {
	if (typeof PublicKeyCredential === 'undefined' || !PublicKeyCredential.parseCreationOptionsFromJSON) {
		throw new Error('Este navegador no soporta passkeys (WebAuthn nivel 3).');
	}
}

function conExtensionPrf<T extends { extensions?: AuthenticationExtensionsClientInputs }>(opciones: T): T {
	return {
		...opciones,
		extensions: { ...opciones.extensions, prf: { eval: { first: PRF_EVAL_SALT } } as PrfExtensionInputs }
	};
}

function resultadoPrf(credencial: PublicKeyCredential): ArrayBuffer | undefined {
	const extensiones = credencial.getClientExtensionResults() as { prf?: PrfExtensionOutputs };
	return extensiones.prf?.results?.first;
}

/**
 * Registra una passkey nueva. `passphrase` es la passphrase actual en claro
 * (ya vive en memoria en el momento del alta, F-38 usa el mismo criterio
 * para su propio setup) — sólo se usa localmente para envolverla con PRF si
 * el autenticador lo soporta; si no, sigue la rama "sin PRF" de siempre
 * (reemplaza el paso HTTP de login, la passphrase se sigue pidiendo para
 * operaciones criptográficas). Devuelve si PRF quedó activo.
 */
export async function registrarPasskey(email: string, passphrase: string, label?: string): Promise<boolean> {
	requerirWebauthnJson();

	const opciones = await api.post<{ publicKey: PublicKeyCredentialCreationOptionsJSON }>(
		'/auth/webauthn/register/options'
	);
	const publicKey = conExtensionPrf(PublicKeyCredential.parseCreationOptionsFromJSON(opciones.publicKey));
	const credencial = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
	if (!credencial) throw new Error('No se pudo crear la passkey.');

	const prfOutput = resultadoPrf(credencial);
	let prfWrappedB64: string | null = null;
	if (prfOutput) {
		const wasm = await cargarCrypto();
		const cifrado = wasm.prf_envolver_passphrase(new Uint8Array(prfOutput), passphrase, aadPrf(email));
		const empaquetado = new Uint8Array(cifrado.nonce.length + cifrado.ciphertext.length);
		empaquetado.set(cifrado.nonce, 0);
		empaquetado.set(cifrado.ciphertext, cifrado.nonce.length);
		prfWrappedB64 = bytesABase64(empaquetado);
	}

	await api.post('/auth/webauthn/register/verify', {
		credential: credencial.toJSON(),
		prf_wrapped_private_key_b64: prfWrappedB64,
		label: label || null
	});

	return prfWrappedB64 !== null;
}

export interface ResultadoLoginPasskey {
	sessionId: string;
	userId: string;
	/** Poblado sólo si esta passkey tiene PRF y el desenvolvimiento local funcionó — el llamador ya puede saltear el prompt de passphrase. */
	claves?: ClavesDesbloqueadas;
}

export async function iniciarSesionConPasskey(email: string): Promise<ResultadoLoginPasskey> {
	requerirWebauthnJson();

	const opciones = await api.post<{ publicKey: PublicKeyCredentialRequestOptionsJSON }>(
		'/auth/webauthn/login/options',
		{ email }
	);
	const publicKey = conExtensionPrf(PublicKeyCredential.parseRequestOptionsFromJSON(opciones.publicKey));
	const credencial = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
	if (!credencial) throw new Error('No se pudo verificar la passkey.');
	const prfOutput = resultadoPrf(credencial);

	const resp = await api.post<{ session_id: string; user_id: string; prf_wrapped_private_key_b64: string | null }>(
		'/auth/webauthn/login/verify',
		{ email, credential: credencial.toJSON() }
	);

	let claves: ClavesDesbloqueadas | undefined;
	if (prfOutput && resp.prf_wrapped_private_key_b64) {
		try {
			const wasm = await cargarCrypto();
			const empaquetado = base64ABytes(resp.prf_wrapped_private_key_b64);
			const nonce = empaquetado.slice(0, 24);
			const ciphertext = empaquetado.slice(24);
			const passphrase = wasm.prf_desenvolver_passphrase(new Uint8Array(prfOutput), nonce, ciphertext, aadPrf(email));
			claves = await desbloquearConPassphrase(email, passphrase);
		} catch {
			// PRF disponible pero el desenvolvimiento falló (ej. passkey
			// registrada en otro dispositivo con un output de PRF distinto) —
			// se degrada al flujo sin PRF, el llamador pide la passphrase.
		}
	}

	return { sessionId: resp.session_id, userId: resp.user_id, claves };
}

export interface Passkey {
	id: string;
	label: string | null;
	createdAt: string;
	lastUsedAt: string | null;
	tienePrf: boolean;
}

interface PasskeyCruda {
	id: string;
	label: string | null;
	created_at: string;
	last_used_at: string | null;
	tiene_prf: boolean;
}

export async function listarPasskeys(): Promise<Passkey[]> {
	const crudas = await api.get<PasskeyCruda[]>('/me/passkeys');
	return crudas.map((p) => ({ id: p.id, label: p.label, createdAt: p.created_at, lastUsedAt: p.last_used_at, tienePrf: p.tiene_prf }));
}

export async function revocarPasskey(id: string): Promise<void> {
	await api.delete(`/me/passkeys/${id}`);
}
