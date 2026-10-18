// Autor: Athan Espinoza

// F-47: sincronización del avatar entre la bóveda de escritorio y el servidor
// vinculado. Reglas:
// - Primera vez conectado: si el servidor tiene foto, gana la del servidor;
//   si no tiene y la app sí, se sube la de la app.
// - Después, el servidor manda: lo que cambie allá (subir/quitar desde la web)
//   se aplica acá en el próximo sync, y lo que se cambie acá se sube al momento
//   (`publicarAvatarLocal`, desde la pantalla de Avatar).
// Para no bajar la imagen en cada sync se guarda el `ETag` (SHA-256) de la
// última versión conocida del servidor y se pregunta con `If-None-Match`.
// El avatar no es un dato secreto (va en claro en los dos lados).

import { get, writable } from 'svelte/store';
import { api, baseUrl } from '$lib/api/client';
import { bytesABase64 } from '$lib/crypto/b64';
import { sesion, clavesDesbloqueadas } from '$lib/state/session';
import { obtenerVinculacion, sesionRemotaVigente, olvidarSesionRemota, claveEstadoAvatar as claveEstado, type VinculacionServidor } from './vinculacion';
import { clienteRemoto } from './remoteClient';

/** Se incrementa cada vez que cambia el avatar local (sync o subida a mano),
 * para que el nav y la pantalla de Avatar lo vuelvan a pedir. */
export const avatarCambiado = writable(0);

interface EstadoAvatar {
	/** `ETag` de la foto del servidor que ya está aplicada acá; `null` = el servidor no tiene. */
	etag: string | null;
	/** Un cambio local no se pudo subir (sin red): se reintenta en el próximo sync. */
	pendiente?: boolean;
}

/** `null` = nunca se reconcilió con este servidor (primera conexión). */
function leerEstado(email: string): EstadoAvatar | null {
	try {
		const crudo = localStorage.getItem(claveEstado(email));
		return crudo ? (JSON.parse(crudo) as EstadoAvatar) : null;
	} catch {
		return null;
	}
}

function guardarEstado(email: string, estado: EstadoAvatar): void {
	try {
		localStorage.setItem(claveEstado(email), JSON.stringify(estado));
	} catch {
		/* sin almacenamiento: la próxima vez se reconcilia de nuevo, sin perder la foto */
	}
}

/** Mismo formato que el `ETag` del servidor (`me::handlers::avatar_obtener`). */
async function etagDe(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
	const hash = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
	return `"${Array.from(hash, (b) => b.toString(16).padStart(2, '0')).join('')}"`;
}

interface Imagen {
	bytes: Uint8Array<ArrayBuffer>;
	contentType: string;
}

async function avatarLocal(): Promise<Imagen | null> {
	const sessionId = get(sesion).sessionId;
	const resp = await fetch(`${await baseUrl()}/me/avatar`, { headers: sessionId ? { Authorization: `Bearer ${sessionId}` } : {} });
	if (resp.status === 404) return null;
	if (!resp.ok) throw new Error(`avatar local: ${resp.status}`);
	return { bytes: new Uint8Array(await resp.arrayBuffer()), contentType: resp.headers.get('content-type') ?? 'image/png' };
}

/** `GET /me/avatar` remoto con `If-None-Match`. El cliente remoto genérico
 * sólo entiende JSON, por eso va con `fetch` directo. Un 401 olvida la
 * sesión reusada y reintenta una vez con una nueva. */
async function pedirAvatarRemoto(
	v: VinculacionServidor,
	etag: string | null
): Promise<{ estado: 'igual' } | { estado: 'sin_avatar' } | { estado: 'nuevo'; imagen: Imagen; etag: string }> {
	const claves = get(clavesDesbloqueadas);
	if (!claves) throw new Error('No hay una sesión desbloqueada.');
	for (let intento = 0; intento < 2; intento++) {
		const headers: Record<string, string> = { Authorization: `Bearer ${await sesionRemotaVigente(v, claves)}` };
		if (etag) headers['If-None-Match'] = etag;
		const resp = await fetch(`${v.serverUrl}/me/avatar`, { headers, cache: 'no-store' });
		if (resp.status === 401 && intento === 0) {
			olvidarSesionRemota(v);
			continue;
		}
		if (resp.status === 304) return { estado: 'igual' };
		if (resp.status === 404) return { estado: 'sin_avatar' };
		if (!resp.ok) throw new Error(`avatar remoto: ${resp.status}`);
		const bytes = new Uint8Array(await resp.arrayBuffer());
		return {
			estado: 'nuevo',
			imagen: { bytes, contentType: resp.headers.get('content-type') ?? 'image/png' },
			etag: resp.headers.get('etag') ?? (await etagDe(bytes))
		};
	}
	throw new Error('avatar remoto: sesión rechazada');
}

async function remotoAutenticado(v: VinculacionServidor) {
	const claves = get(clavesDesbloqueadas);
	if (!claves) throw new Error('No hay una sesión desbloqueada.');
	return clienteRemoto(v.serverUrl, await sesionRemotaVigente(v, claves));
}

/** Sube la foto local (o la quita, si no hay) al servidor y devuelve el nuevo `ETag`. */
async function subirLocalAlServidor(v: VinculacionServidor, imagen: Imagen | null): Promise<string | null> {
	const remoto = await remotoAutenticado(v);
	if (!imagen) {
		await remoto.delete('/me/avatar');
		return null;
	}
	await remoto.put('/me/avatar', { avatar_b64: bytesABase64(imagen.bytes), content_type: imagen.contentType });
	return etagDe(imagen.bytes);
}

/**
 * Reconcilia el avatar con el servidor vinculado. Devuelve `true` si cambió
 * la foto local. La llama `motor.ts::sincronizarAhora` en cada sync.
 */
export async function sincronizarAvatar(): Promise<boolean> {
	const email = get(sesion).email;
	const v = email ? obtenerVinculacion(email) : null;
	if (!email || !v) return false;

	const estado = leerEstado(email);

	// Un cambio hecho acá sin conexión: se sube antes de mirar el servidor.
	if (estado?.pendiente) {
		const etag = await subirLocalAlServidor(v, await avatarLocal());
		guardarEstado(email, { etag });
		return false;
	}

	const remoto = await pedirAvatarRemoto(v, estado?.etag ?? null);
	switch (remoto.estado) {
		case 'igual':
			return false;
		case 'nuevo':
			// Un servidor sin soporte de `If-None-Match` responde 200 siempre.
			if (remoto.etag === estado?.etag) return false;
			await api.put('/me/avatar', { avatar_b64: bytesABase64(remoto.imagen.bytes), content_type: remoto.imagen.contentType });
			guardarEstado(email, { etag: remoto.etag });
			avatarCambiado.update((n) => n + 1);
			return true;
		case 'sin_avatar': {
			if (!estado) {
				// Primera conexión y el servidor no tiene foto: se sube la de la app, si hay.
				const local = await avatarLocal();
				const etag = local ? await subirLocalAlServidor(v, local) : null;
				guardarEstado(email, { etag });
				return false;
			}
			if (estado.etag === null) return false;
			// La quitaron desde la web.
			await api.delete('/me/avatar');
			guardarEstado(email, { etag: null });
			avatarCambiado.update((n) => n + 1);
			return true;
		}
	}
}

/**
 * Después de subir o quitar la foto en la app: si la bóveda está vinculada,
 * la publica en el servidor. Sin conexión queda marcada como pendiente y la
 * sube el próximo sync. Nunca lanza: el cambio local ya está hecho.
 */
export async function publicarAvatarLocal(): Promise<void> {
	avatarCambiado.update((n) => n + 1);
	const email = get(sesion).email;
	const v = email ? obtenerVinculacion(email) : null;
	if (!email || !v || !get(clavesDesbloqueadas)) return;
	try {
		const etag = await subirLocalAlServidor(v, await avatarLocal());
		guardarEstado(email, { etag });
	} catch {
		guardarEstado(email, { etag: leerEstado(email)?.etag ?? null, pendiente: true });
	}
}
