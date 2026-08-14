// Autor: Athan Espinoza

// Login/desbloqueo real contra el backend de Ellkan (F-01/F-02) — mismo
// flujo que `frontend/src/lib/crypto/identity.ts::iniciarSesion`, corrido
// acá (service worker) en vez del hilo principal de una pestaña: `fetch()`
// desde un contexto de extensión con `host_permissions` declarado no está
// sujeto a CORS (a diferencia de un content script, que hereda el origen
// de la página) — no hace falta ningún cambio en el backend para esto.

import { cargarCrypto } from '../wasm';
import { bytesABase64, base64ABytes } from '../../../../frontend/src/lib/crypto/b64';
import { deviceTokenHashB64 } from '../storage/device-storage';
import { SesionStorage } from '../storage/sesion-storage';

function aadClavePrivada(email: string): Uint8Array {
	return new TextEncoder().encode(email);
}

interface ErrorApi {
	error?: { code?: string; message?: string };
}

async function post<T>(serverUrl: string, path: string, body: unknown, sessionId?: string): Promise<T> {
	const headers: Record<string, string> = { 'Content-Type': 'application/json' };
	if (sessionId) headers['Authorization'] = `Bearer ${sessionId}`;

	let resp: Response;
	try {
		resp = await fetch(`${serverUrl}${path}`, { method: 'POST', headers, body: JSON.stringify(body) });
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
	async login(serverUrl: string, email: string, passphrase: string): Promise<ResultadoLogin> {
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
			device_token_hash_b64: deviceTokenHash
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
