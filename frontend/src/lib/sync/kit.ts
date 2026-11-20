// Autor: Athan Espinoza

// F-47: un solo kit de recuperación por cuenta, aunque se use desde la web y
// desde la app de escritorio vinculada. Las dos bóvedas tienen la MISMA
// identidad (mismas claves), así que el registro del kit (pública del kit +
// material sellado a ella) vale igual en los dos lados: alcanza con copiarlo.
// Antes cada lado veía "no hay kit", pedía generar uno y quedaban dos kits
// distintos para la misma cuenta.
//
// Regla: si los dos lados tienen el mismo kit, no se hace nada; si difieren,
// gana el más reciente (generar uno nuevo en cualquier lado reemplaza al del
// otro); si sólo un lado tiene kit, se copia al otro. La privada del kit nunca
// viaja: sólo está en el archivo que descargó el usuario.
//
// `must_rotate` (pendiente #23): usar el kit para recuperar la cuenta en un
// lado lo marca para rotar sólo en ese lado. Como el kit es el mismo, el otro
// lado tiene que quedar marcado también — si no, nunca pediría uno nuevo
// aunque la privada ya se usó. Copiar (`PUT`) limpia la marca en el destino,
// así que se vuelve a poner si el kit copiado la traía.

import { get } from 'svelte/store';
import { api, ApiError } from '$lib/api/client';
import { sesion, clavesDesbloqueadas } from '$lib/state/session';
import { obtenerVinculacion, sesionRemotaVigente } from './vinculacion';
import { clienteRemoto, RemoteApiError } from './remoteClient';

interface RegistroKit {
	kit_public_key_x25519_b64: string;
	sealed_identity_material_b64: string;
	created_at: string;
	must_rotate: boolean;
}

function cuerpo(r: RegistroKit) {
	return { kit_public_key_x25519_b64: r.kit_public_key_x25519_b64, sealed_identity_material_b64: r.sealed_identity_material_b64 };
}

/** `null` si ese lado no tiene kit (404). */
async function o404<T>(p: Promise<T>): Promise<T | null> {
	try {
		return await p;
	} catch (err) {
		if ((err instanceof ApiError || err instanceof RemoteApiError) && err.status === 404) return null;
		throw err;
	}
}

/** Iguala el kit de la bóveda local con el del servidor vinculado. No hace nada sin vinculación. */
export async function sincronizarKit(): Promise<void> {
	const email = get(sesion).email;
	const claves = get(clavesDesbloqueadas);
	const v = email ? obtenerVinculacion(email) : null;
	if (!v || !claves) return;

	const remoto = clienteRemoto(v.serverUrl, await sesionRemotaVigente(v, claves));
	const [local, servidor] = await Promise.all([
		o404(api.get<RegistroKit>('/me/recovery-kit/material')),
		o404(remoto.get<RegistroKit>('/me/recovery-kit/material'))
	]);

	if (!local && !servidor) return;
	const marcarLocal = () => api.post('/me/recovery-kit/must-rotate', {});
	const marcarServidor = () => remoto.post('/me/recovery-kit/must-rotate', {});

	if (local && servidor && local.kit_public_key_x25519_b64 === servidor.kit_public_key_x25519_b64) {
		if (local.must_rotate && !servidor.must_rotate) await marcarServidor();
		else if (servidor.must_rotate && !local.must_rotate) await marcarLocal();
		return;
	}

	const servidorGana = !local || (servidor !== null && Date.parse(servidor.created_at) > Date.parse(local.created_at));
	if (servidorGana && servidor) {
		await api.put('/me/recovery-kit', cuerpo(servidor));
		if (servidor.must_rotate) await marcarLocal();
	} else if (local) {
		await remoto.put('/me/recovery-kit', cuerpo(local));
		if (local.must_rotate) await marcarServidor();
	}
}
