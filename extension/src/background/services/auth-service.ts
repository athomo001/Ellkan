// Autor: Athan Espinoza

// Login/desbloqueo real contra el backend de Ellkan (F-01/F-02) — mismo
// flujo que `frontend/src/lib/crypto/identity.ts::iniciarSesion`, corrido
// acá (service worker) en vez del hilo principal de una pestaña: `fetch()`
// desde un contexto de extensión con `host_permissions` declarado no está
// sujeto a CORS (a diferencia de un content script, que hereda el origen
// de la página) — no hace falta ningún cambio en el backend para esto.

import { cargarCrypto } from '../wasm';
import { bytesABase64, base64ABytes } from '../../../../frontend/src/lib/crypto/b64';
import { deviceTokenHashB64, borrarTokenDeDispositivo } from '../storage/device-storage';
import { SesionStorage } from '../storage/sesion-storage';
import { CuentaStorage } from '../storage/cuenta-storage';

function aadClavePrivada(email: string): Uint8Array {
	return new TextEncoder().encode(email);
}

interface ErrorApi {
	error?: { code?: string; message?: string };
}

async function pedido<T>(
	method: 'GET' | 'POST',
	serverUrl: string,
	path: string,
	body: unknown,
	sessionId?: string
): Promise<T> {
	const headers: Record<string, string> = { 'Content-Type': 'application/json' };
	if (sessionId) headers['Authorization'] = `Bearer ${sessionId}`;

	let resp: Response;
	try {
		resp = await fetch(`${serverUrl}${path}`, { method, headers, body: body ? JSON.stringify(body) : undefined });
	} catch {
		throw new Error(`no se pudo contactar al servidor (${serverUrl}) — ¿está corriendo?`);
	}

	if (!resp.ok) {
		let mensaje = `el servidor respondió ${resp.status}`;
		try {
			const cuerpo = (await resp.json()) as ErrorApi;
			if (cuerpo.error?.message) mensaje = cuerpo.error.message;
		} catch {
			// cuerpo no era JSON — se usa el mensaje genérico de arriba
		}
		throw new Error(mensaje);
	}
	return resp.json() as Promise<T>;
}

async function post<T>(serverUrl: string, path: string, body: unknown, sessionId?: string): Promise<T> {
	return pedido<T>('POST', serverUrl, path, body, sessionId);
}

async function get<T>(serverUrl: string, path: string, sessionId?: string): Promise<T> {
	return pedido<T>('GET', serverUrl, path, undefined, sessionId);
}

export interface ResultadoLogin {
	estado:
		| 'completo'
		| 'pendiente_dispositivo'
		| 'pendiente_mfa'
		| 'requiere_configurar_mfa'
		| 'requiere_cambiar_passphrase';
	sessionId?: string;
	userId?: string;
	deviceChallengeId?: string;
}

export interface EstadoSesionActual {
	sessionId: string;
	email: string;
	serverUrl: string;
}

export const AuthService = {
	/** `forceMfa` (2026-08-15): sólo lo manda `LockService`/la vista de
	 * desbloqueo tras un lock por inactividad — fuerza un código MFA real
	 * aunque este dispositivo ya esté confiado (ver `resolver_tras_f02` en
	 * el backend). En un login normal (primera vez o tras reinicio del
	 * navegador) va en `false`: reinicio pide sólo la passphrase. */
	async login(serverUrl: string, email: string, passphrase: string, forceMfa = false): Promise<ResultadoLogin> {
		const wasm = await cargarCrypto();

		const material = await post<{
			encrypted_private_key_blob_b64: string;
			private_key_nonce_b64: string;
			kdf_salt_b64: string;
		}>(serverUrl, '/auth/key-material', { email });

		const abierta = wasm.abrir_clave_privada(
			passphrase,
			base64ABytes(material.kdf_salt_b64),
			base64ABytes(material.private_key_nonce_b64),
			base64ABytes(material.encrypted_private_key_blob_b64),
			aadClavePrivada(email)
		);

		const challenge = await post<{ nonce_b64: string }>(serverUrl, '/auth/challenge', { email });
		const nonce = base64ABytes(challenge.nonce_b64);
		const firma = wasm.firmar(abierta.ed25519_private, nonce);
		const deviceTokenHash = await deviceTokenHashB64();

		const verify = await post<{
			estado: string;
			session_id?: string;
			user_id?: string;
			device_challenge_id?: string;
		}>(serverUrl, '/auth/verify', {
			email,
			nonce_b64: challenge.nonce_b64,
			signature_b64: bytesABase64(firma),
			device_token_hash_b64: deviceTokenHash,
			force_mfa: forceMfa
		});

		// La firma ya se verificó cripográficamente en este punto (si no,
		// `/auth/verify` de arriba habría fallado) — las claves desenvueltas
		// son válidas independientemente de si falta o no la verificación de
		// dispositivo, así que se guardan ya (nivel 2, `storage.session`).
		// `session_id` sólo se guarda acá si el login ya quedó completo;
		// si falta verificar el dispositivo, `verificarDispositivo()` lo
		// completa después sobre esta misma sesión ya guardada.
		// user_id se guarda ya acá (no sólo cuando el login queda completo) —
		// lo necesita `VaultService.crear()` para el AAD `resource_id||
		// created_by` (mismo formato que `resources/service.rs`), y crear un
		// recurso nuevo no depende de haber pasado la verificación de
		// dispositivo, sólo de tener sesión completa.
		await guardarClaves(serverUrl, email, verify.user_id, abierta.x25519_private, abierta.ed25519_private);
		if (verify.estado === 'completo' && verify.session_id) {
			await SesionStorage.guardar('session_id', verify.session_id);
		} else if (verify.estado === 'pendiente_dispositivo' && verify.device_challenge_id) {
			// El popup de una extensión se cierra solo al perder el foco (ej. el
			// usuario cambia de pestaña para leer el código en su email) — sin
			// esto, `deviceChallengeId` sólo vivía en una variable de `main.ts`
			// y se perdía con el popup, obligando a repetir el login entero
			// aunque las claves ya estuvieran desenvueltas y guardadas arriba.
			// Mismo storage.session que las claves, misma garantía de limpieza.
			await SesionStorage.guardar('device_challenge_id', verify.device_challenge_id);
		}

		// 2026-08-15: servidor+email persistentes (`storage.local`, sobreviven
		// reinicios) — se escriben una única vez, en el primer login real de
		// esta cuenta en este dispositivo. La firma Ed25519 ya se verificó
		// arriba, así que en cualquier `estado` (incluido `pendiente_mfa`) el
		// servidor/email ya son correctos — no hace falta esperar a que el
		// login quede `completo` para dejar de volver a pedirlos.
		if (!(await CuentaStorage.leer())) {
			await CuentaStorage.guardar(serverUrl, email);
		}

		return {
			estado: verify.estado as ResultadoLogin['estado'],
			sessionId: verify.session_id,
			userId: verify.user_id,
			deviceChallengeId: verify.device_challenge_id
		};
	},

	async verificarDispositivo(
		serverUrl: string,
		deviceChallengeId: string,
		codigo: string
	): Promise<{ estado: string; sessionId?: string }> {
		const resp = await post<{ estado: string; session_id?: string; user_id?: string }>(
			serverUrl,
			'/auth/verify-device',
			{ device_challenge_id: deviceChallengeId, code: codigo }
		);
		if (resp.session_id) {
			// Las claves privadas ya se desenvolvieron en `login()` — acá sólo
			// falta completar la sesión con el `session_id` real. `user_id`
			// también llega recién acá (no en `login()`, que para el caso
			// `pendiente_dispositivo` lo manda `None` — confirmado contra
			// `backend/src/auth/handlers.rs`, sin asumir).
			await SesionStorage.guardar('session_id', resp.session_id);
			if (resp.user_id) await SesionStorage.guardar('user_id', resp.user_id);
			await SesionStorage.limpiar('device_challenge_id');
		}
		return { estado: resp.estado, sessionId: resp.session_id };
	},

	/** `POST /auth/mfa/verify` (2026-08-15) — cierra un gap real que ya
	 * existía antes de este pedido: `pendiente_mfa` sólo mostraba "hacelo
	 * desde la web". El Bearer es la sesión PARCIAL que devolvió `login()`
	 * (`sessionIdParcial`); si el código es correcto, esa misma sesión queda
	 * completa server-side (`marcar_mfa_verificada`) — no hay un
	 * `session_id` nuevo que guardar, es el mismo. `device_token_hash_b64`
	 * viaja también acá (spec 2026-08-13, recordar MFA en este dispositivo)
	 * — irrelevante si este login vino con `forceMfa` (el próximo forzado
	 * va a volver a pedir código igual), pero necesario para que un login
	 * NORMAL futuro sí se beneficie del dispositivo ya confiado. */
	async verificarMfa(serverUrl: string, sessionIdParcial: string, codigo: string): Promise<void> {
		const deviceTokenHash = await deviceTokenHashB64();
		await post(serverUrl, '/auth/mfa/verify', { code: codigo, device_token_hash_b64: deviceTokenHash }, sessionIdParcial);

		// `POST /auth/mfa/verify` no devuelve `user_id` (mismo criterio que
		// `/auth/verify` para `pendiente_mfa` — "un solo par de campos
		// relevante a la vez") — `GET /me` sí, ya con la sesión completa.
		const perfil = await get<{ id: string }>(serverUrl, '/me', sessionIdParcial);

		await SesionStorage.guardar('session_id', sessionIdParcial);
		await SesionStorage.guardar('user_id', perfil.id);
	},

	async estadoSesion(): Promise<EstadoSesionActual | null> {
		const sessionId = await SesionStorage.leer('session_id');
		const email = await SesionStorage.leer('email');
		const serverUrl = await SesionStorage.leer('server_url');
		if (!sessionId || !email || !serverUrl) return null;
		return { sessionId, email, serverUrl };
	},

	/** Verificación de dispositivo que quedó a mitad de camino cuando se
	 * cerró el popup (spec 06 §2, ver comentario en `login()`) — permite que
	 * `main.ts` retome directo la vista de "código de verificación" al
	 * reabrirse, en vez de forzar un login desde cero. */
	async estadoPendienteDispositivo(): Promise<{ serverUrl: string; email: string; deviceChallengeId: string } | null> {
		const deviceChallengeId = await SesionStorage.leer('device_challenge_id');
		const email = await SesionStorage.leer('email');
		const serverUrl = await SesionStorage.leer('server_url');
		if (!deviceChallengeId || !email || !serverUrl) return null;
		return { serverUrl, email, deviceChallengeId };
	},

	/** El usuario canceló la verificación pendiente (botón "Volver" en la
	 * vista de código) — limpia el estado local. El `device_challenge_id` en
	 * el servidor simplemente vence solo, no hace falta un endpoint de
	 * cancelación explícito para esto. */
	async cancelarPendienteDispositivo(): Promise<void> {
		for (const clave of ['device_challenge_id', 'email', 'server_url', 'user_id', 'x25519_private', 'ed25519_private']) {
			await SesionStorage.limpiar(clave);
		}
	},

	/** Cuenta persistente (2026-08-15, `CuentaStorage`) — `main.ts` la usa
	 * para decidir qué pantalla mostrar al abrir el popup sin tener que
	 * volver a pedir servidor/email. `locked_reason: 'inactividad'` sólo lo
	 * pone `LockService`; su ausencia con `SesionStorage` vacío significa
	 * reinicio de navegador, no inactividad. */
	async estadoCuenta(): Promise<{ serverUrl: string; email: string; lockedPorInactividad: boolean } | null> {
		const cuenta = await CuentaStorage.leer();
		if (!cuenta) return null;
		return { serverUrl: cuenta.server_url, email: cuenta.email, lockedPorInactividad: cuenta.locked_reason === 'inactividad' };
	},

	async limpiarMarcaDeBloqueo(): Promise<void> {
		await CuentaStorage.limpiarMarcaDeBloqueo();
	},

	/** Cierre de sesión EXPLÍCITO (click deliberado del usuario, spec
	 * 2026-08-15) — único punto que purga todo: servidor/email
	 * (`CuentaStorage`) y el token de dispositivo (`device-storage.ts`),
	 * además de lo que ya limpiaba `SesionStorage`. Un lock por inactividad
	 * o un reinicio de navegador NUNCA pasan por acá — ahí el objetivo es
	 * lo contrario, no volver a pedir nada salvo la passphrase (y el código
	 * MFA si corresponde). El próximo inicio tras esto exige el flujo
	 * completo desde cero: servidor + email + passphrase + verificación de
	 * dispositivo/MFA real, porque el dispositivo ya no es "conocido".
	 */
	async logout(): Promise<void> {
		const sesion = await AuthService.estadoSesion();
		if (sesion) {
			try {
				await post(sesion.serverUrl, '/auth/logout', {}, sesion.sessionId);
			} catch {
				// si la red falla, igual se limpia el estado local — una sesión
				// que el cliente ya no usa no debe quedar "colgada" localmente
				// esperando una respuesta del servidor que puede no llegar nunca.
			}
		}
		for (const clave of ['session_id', 'email', 'server_url', 'user_id', 'x25519_private', 'ed25519_private']) {
			await SesionStorage.limpiar(clave);
		}
		await CuentaStorage.purgar();
		await borrarTokenDeDispositivo();
	}
};

async function guardarClaves(
	serverUrl: string,
	email: string,
	userId: string | undefined,
	x25519Private: Uint8Array,
	ed25519Private: Uint8Array
): Promise<void> {
	await SesionStorage.guardar('server_url', serverUrl);
	await SesionStorage.guardar('email', email);
	if (userId) await SesionStorage.guardar('user_id', userId);
	await SesionStorage.guardar('x25519_private', bytesABase64(x25519Private));
	await SesionStorage.guardar('ed25519_private', bytesABase64(ed25519Private));
}
