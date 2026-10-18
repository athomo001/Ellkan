// Autor: Athan Espinoza

// F-47: vinculación de una bóveda local a un servidor Ellkan remoto —
// "modo conectado", opt-in por bóveda, nunca automático (spec/13 §7).
// Guarda sólo `{serverUrl, email}` en `localStorage` — nunca un
// `session_id` de larga vida: las sesiones remotas vencen por TTL del
// servidor, así que cada sync re-autentica con las claves YA desbloqueadas
// de la sesión local (`$lib/state/session.ts::clavesDesbloqueadas`), sin
// volver a pedir la passphrase ni re-derivar nada.

import { cargarCrypto } from '../crypto/wasm';
import { bytesABase64, base64ABytes } from '../crypto/b64';
import { deviceTokenHashB64 } from '../crypto/device';
import { abrirClavePrivadaEnWorker, sellarClavePrivadaEnWorker } from '../crypto/argon2WorkerClient';
import { api } from '$lib/api/client';
import { clienteRemoto, RemoteApiError } from './remoteClient';
import { olvidarPendientes } from './pendientes';
import { registrar } from '$lib/tauri/registro';
import type { ClavesDesbloqueadas } from '$lib/state/session';

export interface VinculacionServidor {
	serverUrl: string;
	email: string;
	/** Revocación remota: clave pública Ed25519 del servidor, fijada en el
	 * primer sync exitoso (TOFU). Sólo un aviso firmado con ESTA clave puede
	 * ordenar borrar la bóveda (ver `revocacion.ts`). */
	serverKeyB64?: string;
	/** Id de la cuenta (el mismo en la app y en el servidor). */
	userId?: string;
	/** Cuándo se fijó la clave: un aviso emitido antes no vale. */
	fijadaEn?: string;
}

/**
 * Fija la clave del servidor y el id de la cuenta si todavía no estaban
 * (vinculaciones nuevas, o las de antes de la revocación remota). Se llama
 * tras un sync exitoso: recién ahí se sabe que la cuenta y el servidor son
 * los correctos. No cambia una clave ya fijada.
 */
export async function fijarIdentidadDelServidor(email: string, userId: string): Promise<void> {
	const v = obtenerVinculacion(email);
	if (!v || v.serverKeyB64) return;
	const { public_key_ed25519_b64 } = await clienteRemoto(v.serverUrl, null).get<{ public_key_ed25519_b64: string }>('/auth/server-key');
	guardarVinculacion({ ...v, serverKeyB64: public_key_ed25519_b64, userId, fijadaEn: new Date().toISOString() });
}

function claveVinculacion(email: string): string {
	return `ellkan:sync-vinculacion:${email}`;
}

function claveCursor(email: string): string {
	return `ellkan:sync-cursor:${email}`;
}

/** Estado de sync del avatar (`avatar.ts`): sin él, la próxima conexión
 * reconcilia desde cero (gana la foto del servidor; si no tiene, se sube la local). */
export function claveEstadoAvatar(email: string): string {
	return `ellkan:sync-avatar:${email}`;
}

export function obtenerVinculacion(email: string): VinculacionServidor | null {
	const crudo = localStorage.getItem(claveVinculacion(email));
	if (!crudo) return null;
	try {
		return JSON.parse(crudo) as VinculacionServidor;
	} catch {
		return null;
	}
}

function guardarVinculacion(v: VinculacionServidor): void {
	localStorage.setItem(claveVinculacion(v.email), JSON.stringify(v));
}

/** Desvincula — la bóveda sigue funcionando 100% local después de esto
 * (spec/13 §7: "desvincular deja la bóveda funcionando local"), sólo se
 * borra el estado de sync, nunca ningún recurso. */
/** Guarda la vinculación de una cuenta ya autenticada contra ese servidor (la usa `union.ts`). */
export function registrarVinculacion(serverUrl: string, email: string): void {
	guardarVinculacion({ serverUrl, email });
}

export function desvincular(email: string): void {
	localStorage.removeItem(claveVinculacion(email));
	localStorage.removeItem(claveCursor(email));
	localStorage.removeItem(claveEstadoAvatar(email));
	olvidarPendientes(email);
}

export function obtenerCursor(email: string): string | null {
	return localStorage.getItem(claveCursor(email));
}

export function guardarCursor(email: string, cursor: string): void {
	localStorage.setItem(claveCursor(email), cursor);
}

/** Sin cursor, el próximo "Sincronizar ahora" vuelve a bajar todo desde el
 * principio — se usa al volver a "réplica completa" para que los secretos de
 * los recursos que se sincronizaron sin ellos (sólo-memoria/sólo-nombres)
 * se rellenen en disco. */
export function reiniciarCursor(email: string): void {
	localStorage.removeItem(claveCursor(email));
}

/**
 * Autentica contra el servidor remoto usando las claves YA desbloqueadas
 * de la sesión local (sin pedir la passphrase de nuevo). Sólo el camino
 * feliz — `estado: 'completo'`, sin MFA ni verificación de dispositivo del
 * lado remoto: un servidor con esas políticas exigidas no puede vincularse
 * todavía por este camino. Limitación documentada, no un bug silencioso —
 * el error lo dice explícito en vez de colgarse pidiendo un código que
 * nadie va a tipear en un sync de fondo.
 */
async function autenticarContraRemoto(serverUrl: string, email: string, claves: ClavesDesbloqueadas): Promise<string> {
	const diagnostico = await diagnosticarCuentaRemota(serverUrl, email, claves);
	if (diagnostico.estado === 'ok') return diagnostico.sessionId;
	throw new ErrorCuentaRemota(diagnostico);
}

/**
 * Resultado de intentar entrar al servidor remoto con las claves locales.
 * El servidor NO distingue "no existe esa cuenta", "está deshabilitada" y "la
 * clave no coincide" a propósito (anti-enumeración: `/auth/challenge` responde
 * igual para correos que no existen) — por eso todo eso es un único
 * `no_autenticado`; lo que sí se puede distinguir es lo que pasa ANTES de
 * autenticar (sin conexión, no es un servidor Ellkan) y DESPUÉS (pide MFA o
 * verificación de dispositivo).
 */
export type DiagnosticoCuentaRemota =
	| { estado: 'ok'; sessionId: string; userId?: string }
	| { estado: 'sin_conexion' }
	| { estado: 'servidor_invalido' }
	| { estado: 'no_autenticado' }
	/** `sessionId`: la sesión parcial que da el servidor en ese estado (sirve,
	 * por ejemplo, para `POST /me/change-passphrase` si pide cambiar la frase). */
	| { estado: 'requiere_paso_extra'; paso: string; sessionId?: string }
	| { estado: 'error'; mensaje: string };

export type DiagnosticoFallido = Exclude<DiagnosticoCuentaRemota, { estado: 'ok' }>;

/** Mensaje por defecto (español) para quien sólo muestra `err.message`; la UI
 * de Ajustes → Modo conectado traduce `diagnostico.estado` con i18n. */
function mensajeDeDiagnostico(d: DiagnosticoFallido): string {
	switch (d.estado) {
		case 'sin_conexion':
			return 'No se pudo conectar con el servidor — revisá la dirección y tu conexión.';
		case 'servidor_invalido':
			return 'Esa dirección no responde como un servidor Ellkan.';
		case 'no_autenticado':
			return 'El servidor no aceptó esta cuenta: no existe una cuenta con este correo y estas claves, o está deshabilitada.';
		case 'requiere_paso_extra':
			if (d.paso === 'requiere_cambiar_passphrase') {
				return 'El servidor pide cambiar la frase de contraseña de esta cuenta (pasa con las cuentas creadas por un administrador). Entrá una vez por la web, cambiala y volvé a intentar con la frase nueva.';
			}
			return `El servidor remoto pidió un paso extra (${d.paso}) — por ahora la vinculación sólo soporta login directo, sin MFA ni verificación de dispositivo del lado remoto.`;
		case 'error':
			return d.mensaje;
	}
}

/** Error tipado para que la UI pueda traducir el diagnóstico; `message` ya
 * trae el texto por defecto para todo el que sólo lo muestre. */
export class ErrorCuentaRemota extends Error {
	constructor(public diagnostico: DiagnosticoFallido) {
		super(mensajeDeDiagnostico(diagnostico));
	}
}

/** El servidor pide cambiar la frase temporal (cuenta creada por un admin):
 * la UI pide una nueva y vuelve a llamar pasándola. */
export class ErrorRequiereNuevaFrase extends Error {
	constructor() {
		super('El servidor pide cambiar la frase temporal de esta cuenta.');
	}
}

interface MaterialClave {
	encrypted_private_key_blob_b64: string;
	private_key_nonce_b64: string;
	kdf_salt_b64: string;
}

/**
 * Cuenta creada por un admin con frase temporal: el servidor la deja entrar
 * sólo con una sesión parcial que sirve para `POST /me/change-passphrase`
 * (igual que el login web). Re-sella la clave privada con la frase nueva, la
 * cambia en el servidor y devuelve el material nuevo. Sin `passphraseNueva`
 * lanza `ErrorRequiereNuevaFrase` para que la UI la pida.
 */
export async function resolverFraseTemporal(
	serverUrl: string,
	email: string,
	abierta: { x25519Private: Uint8Array; ed25519Private: Uint8Array },
	sessionIdParcial: string | undefined,
	passphraseNueva: string | undefined
): Promise<MaterialClave> {
	if (!passphraseNueva) throw new ErrorRequiereNuevaFrase();
	if (!sessionIdParcial) throw new ErrorCuentaRemota({ estado: 'servidor_invalido' });
	const wasm = await cargarCrypto();
	const salt = wasm.generar_salt_kdf();
	const sellado = await sellarClavePrivadaEnWorker(passphraseNueva, salt, abierta.x25519Private, abierta.ed25519Private, new TextEncoder().encode(email));
	const material: MaterialClave = {
		encrypted_private_key_blob_b64: bytesABase64(sellado.ciphertext),
		private_key_nonce_b64: bytesABase64(sellado.nonce),
		kdf_salt_b64: bytesABase64(salt)
	};
	try {
		await clienteRemoto(serverUrl, sessionIdParcial).post('/me/change-passphrase', material);
	} catch (err) {
		throw new ErrorCuentaRemota({ estado: 'error', mensaje: err instanceof Error ? err.message : String(err) });
	}
	return material;
}

export function esFraseTemporal(d: DiagnosticoCuentaRemota): d is Extract<DiagnosticoCuentaRemota, { estado: 'requiere_paso_extra' }> {
	return d.estado === 'requiere_paso_extra' && d.paso === 'requiere_cambiar_passphrase';
}

function diagnosticoDeError(err: unknown, etapa: 'challenge' | 'verify'): DiagnosticoFallido {
	if (err instanceof RemoteApiError) {
		if (etapa === 'verify' && (err.status === 401 || err.status === 403)) return { estado: 'no_autenticado' };
		if (etapa === 'challenge' && (err.status === 404 || err.status === 405)) return { estado: 'servidor_invalido' };
		return { estado: 'error', mensaje: err.message };
	}
	// `fetch` rechaza con `TypeError` cuando no hay red, el host no resuelve,
	// la URL es inválida o el servidor no habilita CORS.
	if (err instanceof TypeError) return { estado: 'sin_conexion' };
	// Respondió algo que no es JSON (una página HTML, otro servicio).
	if (err instanceof SyntaxError) return { estado: 'servidor_invalido' };
	return { estado: 'error', mensaje: err instanceof Error ? err.message : String(err) };
}

/**
 * Prueba entrar al servidor remoto con las claves YA desbloqueadas de la
 * sesión local (sin pedir la passphrase de nuevo) y dice qué pasó, sin
 * lanzar. Es lo que valida, antes de conectar o de elegir un modo de
 * persistencia que necesita el servidor (`memory`/`names_only`), que esta
 * cuenta tiene una cuenta habilitada allá.
 */
export async function diagnosticarCuentaRemota(
	serverUrl: string,
	email: string,
	claves: ClavesDesbloqueadas
): Promise<DiagnosticoCuentaRemota> {
	const wasm = await cargarCrypto();
	const remoto = clienteRemoto(serverUrl, null);

	let challenge: { nonce_b64?: string } | undefined;
	try {
		challenge = await remoto.post<{ nonce_b64: string }>('/auth/challenge', { email });
	} catch (err) {
		return diagnosticoDeError(err, 'challenge');
	}
	if (!challenge?.nonce_b64) return { estado: 'servidor_invalido' };

	const firma = wasm.firmar(claves.ed25519Private, base64ABytes(challenge.nonce_b64));
	const deviceTokenHash = await deviceTokenHashB64();

	let verify: { estado: string; session_id?: string; user_id?: string } | undefined;
	try {
		verify = await remoto.post<{ estado: string; session_id?: string; user_id?: string }>('/auth/verify', {
			email,
			nonce_b64: challenge.nonce_b64,
			signature_b64: bytesABase64(firma),
			device_token_hash_b64: deviceTokenHash
		});
	} catch (err) {
		return diagnosticoDeError(err, 'verify');
	}

	if (verify?.estado !== 'completo' || !verify.session_id) {
		return { estado: 'requiere_paso_extra', paso: verify?.estado ?? 'desconocido', sessionId: verify?.session_id };
	}
	return { estado: 'ok', sessionId: verify.session_id, userId: verify.user_id };
}

/**
 * Sesión remota vigente. Se reusa en memoria (nunca en disco) hasta
 * `VIDA_SESION_REMOTA_MS`: con el sync automático cada pocos segundos,
 * autenticar en cada llamada crearía una sesión nueva en el servidor cada vez
 * (que nunca se cierra). Si el servidor la rechaza antes (401), quien la usa
 * llama a `olvidarSesionRemota` y reintenta.
 */
const VIDA_SESION_REMOTA_MS = 10 * 60_000;
const sesionesRemotas = new Map<string, { sessionId: string; vence: number }>();

export async function sesionRemotaVigente(v: VinculacionServidor, claves: ClavesDesbloqueadas): Promise<string> {
	const clave = `${v.serverUrl}|${v.email}`;
	const guardada = sesionesRemotas.get(clave);
	if (guardada && guardada.vence > Date.now()) return guardada.sessionId;
	let sessionId: string;
	try {
		sessionId = await autenticarContraRemoto(v.serverUrl, v.email, claves);
		registrar('info', `[servidor] sesión iniciada en ${v.serverUrl}`);
	} catch (err) {
		registrar('warn', `[servidor] no se pudo iniciar sesión en ${v.serverUrl}:`, err);
		// El servidor ya no acepta esta cuenta: puede que la hayan bloqueado o
		// borrado. Se le pregunta con una consulta firmada (revocación remota);
		// nunca se borra nada sólo por este error.
		if (err instanceof ErrorCuentaRemota && err.diagnostico.estado === 'no_autenticado') {
			void import('./revocacion').then((m) => m.comprobarEstadoCuenta(v, claves)).catch(() => {});
		}
		throw err;
	}
	sesionesRemotas.set(clave, { sessionId, vence: Date.now() + VIDA_SESION_REMOTA_MS });
	return sessionId;
}

export function olvidarSesionRemota(v: VinculacionServidor): void {
	sesionesRemotas.delete(`${v.serverUrl}|${v.email}`);
}

/** (a) "Ya tengo cuenta en ese servidor" — valida el login real contra el
 * servidor remoto (mismas claves, ninguna passphrase nueva) y recién
 * después guarda la vinculación — nunca se guarda un servidor al que ni
 * siquiera se pudo entrar. */
export async function vincularConCuentaExistente(serverUrl: string, email: string, claves: ClavesDesbloqueadas): Promise<void> {
	await autenticarContraRemoto(serverUrl, email, claves);
	guardarVinculacion({ serverUrl, email });
}

/**
 * (b) "Bóveda local nueva que quiero respaldar" — registra la MISMA
 * identidad (mismo blob cifrado, nunca una clave nueva) en el servidor
 * remoto. Reusa `POST /auth/key-material` LOCAL (mismo endpoint que ya usa
 * el login normal, sin auth de sesión — pensado justo para leer el propio
 * material cifrado) en vez de volver a cifrar nada: la passphrase sigue
 * siendo la misma en los dos lados sin que este código la vea en ningún
 * momento. Las claves PÚBLICAS vienen de `claves` (ya derivadas al
 * desbloquear, `wasm.clave_publica_*_de` en `identity.ts::iniciarSesion`)
 * — ningún endpoint HTTP las expone sueltas.
 */
export async function vincularComoBovedaNueva(
	serverUrl: string,
	email: string,
	displayName: string,
	claves: ClavesDesbloqueadas
): Promise<void> {
	const material = await api.post<{
		encrypted_private_key_blob_b64: string;
		private_key_nonce_b64: string;
		kdf_salt_b64: string;
	}>('/auth/key-material', { email });

	const remoto = clienteRemoto(serverUrl, null);
	try {
		await remoto.post('/auth/register', {
			email,
			display_name: displayName,
			public_key_x25519_b64: bytesABase64(claves.x25519Public),
			public_key_ed25519_b64: bytesABase64(claves.ed25519Public),
			encrypted_private_key_blob_b64: material.encrypted_private_key_blob_b64,
			private_key_nonce_b64: material.private_key_nonce_b64,
			kdf_salt_b64: material.kdf_salt_b64
		});
	} catch (err) {
		// Un fallo de red no debería verse como "Failed to fetch" crudo.
		if (err instanceof TypeError) throw new ErrorCuentaRemota({ estado: 'sin_conexion' });
		throw err;
	}

	guardarVinculacion({ serverUrl, email });
}

/**
 * Primer arranque de la app conectado a una cuenta que YA existe en un
 * servidor (F-47). Al revés que las dos opciones de arriba: no se vincula una
 * bóveda local existente, se crea la bóveda local con la identidad del
 * servidor — mismas claves, mismo blob cifrado (se desbloquea con la misma
 * passphrase) y el mismo id de usuario, para que todo lo cifrado de un lado
 * se pueda leer del otro (el id del creador va en el AAD de cada recurso).
 *
 * La passphrase sólo se usa acá, localmente, para abrir el material que manda
 * el servidor (nunca viaja). Si es incorrecta, o la cuenta no existe (el
 * servidor responde igual en los dos casos, anti-enumeración), falla al
 * abrir el material. Después del alta local hay que iniciar sesión local
 * normal con el mismo correo y passphrase.
 */
export async function conectarDesdeServidor(
	serverUrlCrudo: string,
	email: string,
	passphrase: string,
	passphraseNueva?: string
): Promise<void> {
	const serverUrl = serverUrlCrudo.trim().replace(/\/+$/, '');
	const wasm = await cargarCrypto();
	const remoto = clienteRemoto(serverUrl, null);

	let material: { encrypted_private_key_blob_b64: string; private_key_nonce_b64: string; kdf_salt_b64: string };
	try {
		material = await remoto.post('/auth/key-material', { email });
	} catch (err) {
		throw new ErrorCuentaRemota(diagnosticoDeError(err, 'challenge'));
	}

	let abierta: { x25519Private: Uint8Array; ed25519Private: Uint8Array };
	try {
		abierta = await abrirClavePrivadaEnWorker(
			passphrase,
			base64ABytes(material.kdf_salt_b64),
			base64ABytes(material.private_key_nonce_b64),
			base64ABytes(material.encrypted_private_key_blob_b64),
			new TextEncoder().encode(email)
		);
	} catch {
		throw new ErrorCuentaRemota({ estado: 'error', mensaje: 'Correo o frase de contraseña incorrectos para ese servidor.' });
	}
	const claves: ClavesDesbloqueadas = {
		x25519Private: abierta.x25519Private,
		ed25519Private: abierta.ed25519Private,
		x25519Public: wasm.clave_publica_x25519_de(abierta.x25519Private),
		ed25519Public: wasm.clave_publica_ed25519_de(abierta.ed25519Private)
	};

	let diagnostico = await diagnosticarCuentaRemota(serverUrl, email, claves);
	// Cuenta nueva creada por un admin: la frase es temporal y se cambia acá
	// mismo; la bóveda local nace ya con la frase nueva.
	if (esFraseTemporal(diagnostico)) {
		material = await resolverFraseTemporal(serverUrl, email, abierta, diagnostico.sessionId, passphraseNueva);
		diagnostico = await diagnosticarCuentaRemota(serverUrl, email, claves);
	}
	if (diagnostico.estado !== 'ok') throw new ErrorCuentaRemota(diagnostico);
	if (!diagnostico.userId) throw new ErrorCuentaRemota({ estado: 'servidor_invalido' });

	let displayName = email;
	try {
		const perfil = await clienteRemoto(serverUrl, diagnostico.sessionId).get<{ display_name: string }>('/me');
		displayName = perfil.display_name || email;
	} catch {
		// El nombre visible es sólo cosmético: si falla, queda el correo.
	}

	await api.post('/auth/register-desde-servidor', {
		email,
		display_name: displayName,
		public_key_x25519_b64: bytesABase64(claves.x25519Public),
		public_key_ed25519_b64: bytesABase64(claves.ed25519Public),
		encrypted_private_key_blob_b64: material.encrypted_private_key_blob_b64,
		private_key_nonce_b64: material.private_key_nonce_b64,
		kdf_salt_b64: material.kdf_salt_b64,
		user_id: diagnostico.userId
	});
	guardarVinculacion({ serverUrl, email });
}
