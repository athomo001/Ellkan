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
import { api } from '$lib/api/client';
import { clienteRemoto, RemoteApiError } from './remoteClient';
import type { ClavesDesbloqueadas } from '$lib/state/session';

export interface VinculacionServidor {
	serverUrl: string;
	email: string;
}

function claveVinculacion(email: string): string {
	return `ellkan:sync-vinculacion:${email}`;
}

function claveCursor(email: string): string {
	return `ellkan:sync-cursor:${email}`;
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
export function desvincular(email: string): void {
	localStorage.removeItem(claveVinculacion(email));
	localStorage.removeItem(claveCursor(email));
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
	| { estado: 'ok'; sessionId: string }
	| { estado: 'sin_conexion' }
	| { estado: 'servidor_invalido' }
	| { estado: 'no_autenticado' }
	| { estado: 'requiere_paso_extra'; paso: string }
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

	let verify: { estado: string; session_id?: string } | undefined;
	try {
		verify = await remoto.post<{ estado: string; session_id?: string }>('/auth/verify', {
			email,
			nonce_b64: challenge.nonce_b64,
			signature_b64: bytesABase64(firma),
			device_token_hash_b64: deviceTokenHash
		});
	} catch (err) {
		return diagnosticoDeError(err, 'verify');
	}

	if (verify?.estado !== 'completo' || !verify.session_id) {
		return { estado: 'requiere_paso_extra', paso: verify?.estado ?? 'desconocido' };
	}
	return { estado: 'ok', sessionId: verify.session_id };
}

/** Devuelve una sesión remota vigente — re-autentica en cada llamada (sin
 * cachear el `session_id`, ver comentario del módulo). El costo de un
 * challenge/verify extra por sync es insignificante comparado con la
 * complejidad de manejar expiración de sesión remota como un caso aparte. */
export async function sesionRemotaVigente(v: VinculacionServidor, claves: ClavesDesbloqueadas): Promise<string> {
	return autenticarContraRemoto(v.serverUrl, v.email, claves);
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
