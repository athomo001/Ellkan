// Autor: Athan Espinoza

// F-01/F-38: primera superficie real donde corre la cadena
// Argon2id→HKDF→AEAD dentro de un navegador de verdad — orquesta el WASM
// (`ellkan_crypto`) con las llamadas HTTP reales, la passphrase nunca sale
// de esta capa hacia el resto de la app (ni se loguea, ni cruza a Sentry
// si algún día se agrega uno).

import { cargarCrypto } from './wasm';
import { bytesABase64, base64ABytes } from './b64';
import { api } from '#lib/api/client';
import { deviceTokenHashB64 } from './device';
import type { ClavesDesbloqueadas } from '#lib/state/session';
import { limpiarStoresEn } from '#lib/state/declarative-store';
import { olvidarClaveDeCache } from '#lib/cache/metadataCache';
import {
	abrirMaterial,
	aplicarMejoraKdf,
	camposDelBlob,
	mejorarKdf,
	prepararMejoraKdf,
	pruebaDePosesion,
	sellarNuevo,
	type MaterialClave,
	type MejoraKdfPendiente
} from './desbloqueo';
import type { ResultadoAbrir } from './argon2WorkerClient';

export type { MaterialClave };

function clavesDe(wasm: Awaited<ReturnType<typeof cargarCrypto>>, abierta: ResultadoAbrir): ClavesDesbloqueadas {
	return {
		x25519Private: abierta.x25519Private,
		ed25519Private: abierta.ed25519Private,
		x25519Public: wasm.clave_publica_x25519_de(abierta.x25519Private),
		ed25519Public: wasm.clave_publica_ed25519_de(abierta.ed25519Private)
	};
}

/** QA-03: mejora del sellado preparada en el último login de una cuenta
 * vieja, para aplicar cuando la sesión quede completa (`aplicarMejoraKdfPendiente`). */
let mejoraPendiente: MejoraKdfPendiente | undefined;

/** QA-03: si el último login fue de una cuenta sellada antes de QA-03, la
 * re-sella ahora (la sesión ya es completa). Nunca tira: si falla, se
 * reintenta en el próximo login. */
export async function aplicarMejoraKdfPendiente(ed25519Private: Uint8Array | undefined): Promise<void> {
	const mejora = mejoraPendiente;
	mejoraPendiente = undefined;
	if (!mejora || !ed25519Private) return;
	try {
		await aplicarMejoraKdf(api.post, mejora, ed25519Private);
	} catch {
		/* se reintenta en el próximo login */
	}
}

/** El email con el que se selló el blob (ver `MaterialClave`). */
export function emailDelMaterial(material: MaterialClave, tipeado: string): string {
	return material.email ?? tipeado.trim();
}

interface ResultadoRegistro {
	userId: string;
	/** F-24: `true` en cualquier auto-registro normal — la cuenta no puede
	 * loguear todavía, hay que verificar el email con `verificarEmail`
	 * antes. `false` sólo en el bootstrap (primer usuario de la instancia). */
	pendingVerification: boolean;
}

/** QA-11: token de instalación que el operador pasa en el fragmento de la
 * URL de registro (`/register#setup=<token>`). El fragmento nunca viaja en
 * la request ni queda en logs de proxy; el servidor sólo lo mira para el
 * primer registro de una instancia vacía y si `ELLKAN_SETUP_TOKEN` está
 * configurado. */
function tokenDeInstalacionDeLaUrl(): string | undefined {
	if (typeof location === 'undefined') return undefined;
	const valor = new URLSearchParams(location.hash.replace(/^#/, '')).get('setup');
	return valor || undefined;
}

/** Pendiente #109: si la instancia está vacía, el primer registro (que nace
 * admin) tiene que presentar el token de instalación. */
export async function requiereTokenDeInstalacion(): Promise<boolean> {
	const resp = await api.get<{ setup_token_required: boolean }>('/auth/setup-status');
	return resp.setup_token_required;
}

/** Token de instalación del fragmento de la URL, para precargar el campo. */
export function tokenDeInstalacionInicial(): string {
	return tokenDeInstalacionDeLaUrl() ?? '';
}

export async function registrar(
	email: string,
	displayName: string,
	passphrase: string,
	tokenInstalacion?: string
): Promise<ResultadoRegistro> {
	const wasm = await cargarCrypto();
	const identidad = wasm.generar_identidad();
	const blob = await sellarNuevo(passphrase, identidad.x25519_private, identidad.ed25519_private, email);

	const resp = await api.post<{ user_id: string; pending_verification: boolean }>('/auth/register', {
		email,
		display_name: displayName,
		public_key_x25519_b64: bytesABase64(identidad.x25519_public),
		public_key_ed25519_b64: bytesABase64(identidad.ed25519_public),
		...camposDelBlob(blob),
		setup_token: tokenInstalacion?.trim() || tokenDeInstalacionDeLaUrl()
	});
	return { userId: resp.user_id, pendingVerification: resp.pending_verification };
}

/** Pendiente #133: primer acceso de una cuenta creada por SSO (JIT), que
 * nace sin claves. Mismo armado que `registrar` (identidad nueva, blob
 * sellado con la contraseña que elige el usuario y su email como AAD), pero
 * contra `POST /me/keys/enroll`, que el servidor acepta una sola vez.
 * Devuelve las claves ya abiertas para no volver a pedir la contraseña. */
export async function enrolarClaves(email: string, passphrase: string): Promise<ClavesDesbloqueadas> {
	const wasm = await cargarCrypto();
	const identidad = wasm.generar_identidad();
	const blob = await sellarNuevo(passphrase, identidad.x25519_private, identidad.ed25519_private, email);
	await api.post('/me/keys/enroll', {
		public_key_x25519_b64: bytesABase64(identidad.x25519_public),
		public_key_ed25519_b64: bytesABase64(identidad.ed25519_public),
		...camposDelBlob(blob)
	});
	return {
		x25519Private: identidad.x25519_private,
		ed25519Private: identidad.ed25519_private,
		x25519Public: identidad.x25519_public,
		ed25519Public: identidad.ed25519_public
	};
}

/** Parte C: mismo shape que `registrar`, pero contra `POST /admin/users`
 * (requiere permiso `*`) — salta la política de auto-registro y el
 * requisito de SMTP configurado, la cuenta queda verificada de una. */
export async function crearUsuarioPorAdmin(email: string, displayName: string, passphrase: string): Promise<ResultadoRegistro> {
	const wasm = await cargarCrypto();
	const identidad = wasm.generar_identidad();
	const blob = await sellarNuevo(passphrase, identidad.x25519_private, identidad.ed25519_private, email);

	const resp = await api.post<{ user_id: string; pending_verification: boolean }>('/admin/users', {
		email,
		display_name: displayName,
		public_key_x25519_b64: bytesABase64(identidad.x25519_public),
		public_key_ed25519_b64: bytesABase64(identidad.ed25519_public),
		...camposDelBlob(blob)
	});
	return { userId: resp.user_id, pendingVerification: resp.pending_verification };
}

/** F-24: código de 6 dígitos enviado por email tras un auto-registro normal. */
export async function verificarEmail(email: string, code: string): Promise<void> {
	await api.post('/auth/verify-email', { email, code });
}

/** Anti-enumeration: la misma respuesta exista o no la cuenta, ya esté
 * verificada o no — nunca lanza por esas razones. */
export async function reenviarVerificacionEmail(email: string): Promise<void> {
	await api.post('/auth/verify-email/resend', { email });
}

interface ResultadoLogin {
	estado:
		| 'completo'
		| 'pendiente_dispositivo'
		| 'pendiente_mfa'
		| 'requiere_configurar_mfa'
		| 'requiere_cambiar_passphrase';
	sessionId?: string;
	userId?: string;
	deviceChallengeId?: string;
	claves?: ClavesDesbloqueadas;
	/** QA-16: el email tal como está guardado — es el que va a la sesión. */
	email: string;
}

/**
 * F-01/F-02: prelogin→Argon2id→key-material→abrir→challenge→firma→verify. A
 * diferencia de la CLI (que cachea el blob cifrado en un perfil local tras
 * registrarse), un navegador sin estado local lo pide en cada login; desde
 * QA-03 sólo lo recibe probando la `auth_key` (ver `desbloqueo.ts`). Si la
 * cuenta está sellada con el esquema anterior, deja preparada la mejora para
 * `aplicarMejoraKdfPendiente` (la sesión puede no estar completa todavía).
 */
export async function iniciarSesion(email: string, passphrase: string): Promise<ResultadoLogin> {
	const wasm = await cargarCrypto();

	const desbloqueado = await abrirMaterial(api.post, email, passphrase);
	const { abierta, email: emailGuardado } = desbloqueado;
	mejoraPendiente = await prepararMejoraKdf(desbloqueado, passphrase);

	const challenge = await api.post<{ nonce_b64: string }>('/auth/challenge', { email });
	const nonce = base64ABytes(challenge.nonce_b64);
	const firma = wasm.firmar(abierta.ed25519Private, nonce);
	const deviceTokenHash = await deviceTokenHashB64();

	const verify = await api.post<{
		estado: string;
		session_id?: string;
		user_id?: string;
		device_challenge_id?: string;
	}>('/auth/verify', {
		email,
		nonce_b64: challenge.nonce_b64,
		signature_b64: bytesABase64(firma),
		device_token_hash_b64: deviceTokenHash
	});

	const claves = clavesDe(wasm, abierta);

	return {
		estado: verify.estado as ResultadoLogin['estado'],
		sessionId: verify.session_id,
		userId: verify.user_id,
		deviceChallengeId: verify.device_challenge_id,
		claves,
		email: emailGuardado
	};
}

/**
 * F-04: invalida la sesión server-side (`sessions`) y limpia todo lo que
 * `declararStore` tenga registrado con `clearOn: ['logout']` — la clave
 * privada nunca sobrevive a un logout. Si la request de red falla (ej. sin
 * conexión) igual limpia el estado local: un logout que se queda colgado
 * dejando la clave privada en memoria es peor que uno que no le avisó al
 * servidor a tiempo, la sesión igual expira por TTL del lado del backend.
 */
export async function cerrarSesion(): Promise<void> {
	try {
		await api.post('/auth/logout');
	} finally {
		limpiarStoresEn('logout');
		// F-30: la clave efímera del cache de metadata (IndexedDB) vive en
		// sessionStorage — sin ella el ciphertext cacheado queda inerte.
		olvidarClaveDeCache();
	}
}

/**
 * F-38 (setup del desbloqueo rápido local): confirma que `passphrase` es
 * la correcta para `email` sin completar un login — mismo material que
 * `iniciarSesion` (`/auth/key-material` + `abrir_clave_privada`), pero
 * nunca llega a `/auth/challenge`/`/auth/verify`. Tira si es incorrecta.
 */
export async function verificarPassphrase(email: string, passphrase: string): Promise<void> {
	await abrirMaterial(api.post, email, passphrase);
}

/**
 * F-39 (reanudar tras auto-bloqueo): reconstruye la clave privada a partir
 * de la passphrase, sin pasar por `/auth/challenge`/`/auth/verify` — la
 * sesión HTTP nunca se cerró, no hace falta un login nuevo, sólo volver a
 * desenvolver localmente lo que el auto-bloqueo descartó de memoria.
 */
export async function desbloquearConPassphrase(email: string, passphrase: string): Promise<ClavesDesbloqueadas> {
	const wasm = await cargarCrypto();
	const d = await abrirMaterial(api.post, email, passphrase);
	// QA-03: la sesión ya es completa, así que una cuenta vieja se re-sella acá.
	if (d.legado) await mejorarKdf(api.post, d.email, passphrase, d.abierta).catch(() => {});
	return clavesDe(wasm, d.abierta);
}

/**
 * F-01 (cambio de passphrase): abre el blob viejo con la passphrase actual
 * (mismo material que `verificarPassphrase`) y lo re-sella con la nueva —
 * el servidor nunca ve ninguna de las dos, sólo el blob ya re-sellado.
 * `POST /me/change-passphrase` rota `security_stamp` server-side, así que
 * **esta misma sesión queda invalidada al terminar** — el caller debe
 * tratar eso como éxito y redirigir a login, nunca como error.
 */
export async function cambiarPassphrase(
	email: string,
	passphraseActual: string,
	passphraseNueva: string
): Promise<void> {
	const { abierta, email: emailGuardado, userId } = await abrirMaterial(api.post, email, passphraseActual);
	// #49: el blob nuevo ya va con el `user_id` como AAD (si el servidor lo da).
	const blob = await sellarNuevo(passphraseNueva, abierta.x25519Private, abierta.ed25519Private, emailGuardado, { userId });
	// QA-06: la sesión sola no alcanza para reemplazar el blob.
	const prueba = await pruebaDePosesion(api.post, email, abierta.ed25519Private, blob);
	await api.post('/me/change-passphrase', { ...camposDelBlob(blob), ...prueba });
}

/**
 * Modo escritorio (cuenta local única): cambia el correo de la cuenta. El
 * correo es el AAD del blob de la clave privada (`aadClavePrivada`), así que
 * no alcanza con actualizar la fila de `users` — hay que abrir el blob con la
 * passphrase y el correo actual, y re-sellarlo con el correo nuevo. Mismo
 * patrón que `cambiarPassphrase`, con la diferencia de que acá la passphrase
 * no cambia (sólo el AAD y, de paso, la sal del KDF). Una passphrase
 * incorrecta falla al abrir el blob, antes de tocar nada en el backend, así
 * que esto también sirve de confirmación de identidad.
 *
 * `PUT /me/email` sólo existe en el backend de escritorio. Devuelve el
 * correo tal como quedó guardado (ya recortado).
 */
export async function cambiarEmailDeCuenta(emailActual: string, emailNuevo: string, passphrase: string): Promise<string> {
	const { abierta } = await abrirMaterial(api.post, emailActual, passphrase);
	const nuevoEmail = emailNuevo.trim();
	const blob = await sellarNuevo(passphrase, abierta.x25519Private, abierta.ed25519Private, nuevoEmail);
	const resp = await api.put<{ email: string }>('/me/email', { new_email: nuevoEmail, ...camposDelBlob(blob) });
	return resp.email;
}

export async function verificarDispositivo(
	deviceChallengeId: string,
	codigo: string
): Promise<{ estado: string; sessionId?: string; userId?: string }> {
	const resp = await api.post<{ estado: string; session_id?: string; user_id?: string }>(
		'/auth/verify-device',
		{ device_challenge_id: deviceChallengeId, code: codigo }
	);
	return { estado: resp.estado, sessionId: resp.session_id, userId: resp.user_id };
}
