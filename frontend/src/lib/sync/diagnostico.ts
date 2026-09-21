// Autor: Athan Espinoza

// Punto 7 (diagnóstico del traspaso de datos): junta lo que hay en el
// servidor remoto vinculado y en la bóveda local y se lo pasa a
// `compararTraspaso` (`traspaso.ts`, la parte pura). Sólo lee — nunca
// escribe en ninguno de los dos lados — y no descifra nada: compara bytes
// cifrados, así que no necesita las claves más que para autenticarse contra
// el servidor, igual que `sincronizarAhora`.

import { get } from 'svelte/store';
import { api, ApiError } from '$lib/api/client';
import { sesion, clavesDesbloqueadas } from '$lib/state/session';
import { obtenerVinculacion, sesionRemotaVigente } from './vinculacion';
import { clienteRemoto, RemoteApiError } from './remoteClient';
import { obtenerPersistencia } from './persistencia';
import {
	compararTraspaso,
	type EnvelopeB64,
	type InformeTraspaso,
	type RecursoLocal,
	type RecursoRemoto
} from './traspaso';

interface RecursoListado {
	id: string;
	metadata_ciphertext_b64: string;
	metadata_nonce_b64: string;
}

interface EnvelopeCrudo {
	sealed_dek_b64: string;
	secret_ciphertext_b64: string;
	secret_nonce_b64: string;
}

function aEnvelope(e: EnvelopeCrudo): EnvelopeB64 {
	return { sealedDekB64: e.sealed_dek_b64, secretCiphertextB64: e.secret_ciphertext_b64, secretNonceB64: e.secret_nonce_b64 };
}

/** Pide de a `tamano` a la vez: es una herramienta de desarrollo sobre una
 * bóveda real, no hace falta abrir cientos de conexiones en paralelo. */
async function enLotes<T, R>(items: T[], tamano: number, fn: (item: T) => Promise<R>): Promise<R[]> {
	const resultado: R[] = [];
	for (let i = 0; i < items.length; i += tamano) {
		resultado.push(...(await Promise.all(items.slice(i, i + tamano).map(fn))));
	}
	return resultado;
}

/** 404 = "no hay" (esperado en modos sin réplica del secreto); cualquier otro
 * error sí se propaga — un 500 no es "no hay". */
async function o404<T>(promesa: Promise<T>): Promise<T | null> {
	try {
		return await promesa;
	} catch (err) {
		if (err instanceof ApiError && err.status === 404) return null;
		throw err;
	}
}

export async function verificarTraspaso(): Promise<InformeTraspaso> {
	const email = get(sesion).email;
	const claves = get(clavesDesbloqueadas);
	if (!email || !claves) throw new Error('No hay una sesión desbloqueada.');

	const vinculacion = obtenerVinculacion(email);
	if (!vinculacion) throw new Error('Esta bóveda no está conectada a ningún servidor.');

	const modo = await obtenerPersistencia();
	const sessionId = await sesionRemotaVigente(vinculacion, claves);
	const remoto = clienteRemoto(vinculacion.serverUrl, sessionId);

	const [listadoRemoto, listadoLocal] = await Promise.all([
		remoto.get<RecursoListado[]>('/resources'),
		api.get<RecursoListado[]>('/resources')
	]);

	const remotos: RecursoRemoto[] = await enLotes(listadoRemoto, 8, async (r) => {
		let secreto: EnvelopeB64 | null = null;
		try {
			secreto = aEnvelope(await remoto.get<EnvelopeCrudo>(`/resources/${r.id}/secret`));
		} catch (err) {
			// Un error del servidor al pedir el envelope es un dato del
			// diagnóstico (`secreto: null`), no algo que aborte todo el informe.
			if (!(err instanceof RemoteApiError || err instanceof TypeError)) throw err;
		}
		return { id: r.id, metadataCiphertextB64: r.metadata_ciphertext_b64, metadataNonceB64: r.metadata_nonce_b64, secreto };
	});

	const locales: RecursoLocal[] = await enLotes(listadoLocal, 8, async (r) => {
		const envelope = await o404(api.get<EnvelopeCrudo>(`/resources/${r.id}/secret`));
		const dek = envelope ? null : await o404(api.get<{ sealed_dek_b64: string }>(`/resources/${r.id}/metadata-dek`));
		return {
			id: r.id,
			metadataCiphertextB64: r.metadata_ciphertext_b64,
			metadataNonceB64: r.metadata_nonce_b64,
			secretoLocal: envelope ? aEnvelope(envelope) : null,
			dekLocalB64: dek?.sealed_dek_b64 ?? null
		};
	});

	return compararTraspaso({ modo, remotos, locales });
}
