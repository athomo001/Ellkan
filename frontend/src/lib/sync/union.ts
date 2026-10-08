// Autor: Athan Espinoza

// F-47, parte B: unir una bóveda local que ya existe con la cuenta del MISMO
// correo en un servidor, cuando las dos se crearon por separado (claves
// distintas). Para quien la usa es "dirección + frase del servidor"; por
// dentro:
//   1. abre la identidad del servidor con esa frase (localmente, nunca viaja);
//   2. descifra cada recurso local y lo vuelve a cifrar para esa identidad
//      (DEK nueva sellada a su clave pública, AAD con su id), y lo sube junto
//      con las carpetas — si algo falla acá, la bóveda local sigue intacta;
//   3. hace una copia de seguridad local;
//   4. reemplaza la identidad local por la del servidor (una transacción en
//      el backend de escritorio, `POST /auth/adoptar-identidad`);
//   5. entra con la frase del servidor y sincroniza: todo vuelve, ya con la
//      identidad nueva, junto con lo que el servidor ya tenía.
// Desde ahí la app se desbloquea con la frase del SERVIDOR (decisión del
// usuario, 2026-10-04). Los tags no se trasladan en esta primera versión.

import { get } from 'svelte/store';
import { api, ApiError } from '$lib/api/client';
import { cargarCrypto } from '$lib/crypto/wasm';
import { bytesABase64, base64ABytes } from '$lib/crypto/b64';
import { uuidABytes } from '$lib/crypto/uuid';
import { abrirClavePrivadaEnWorker } from '$lib/crypto/argon2WorkerClient';
import { iniciarSesion } from '$lib/crypto/identity';
import { listarArbolCarpetas } from '$lib/crypto/carpetas';
import { desactivar as desactivarLlavero } from '$lib/crypto/llavero-local';
import { sesion, clavesDesbloqueadas, type ClavesDesbloqueadas } from '$lib/state/session';
import { clienteRemoto, RemoteApiError } from './remoteClient';
import { diagnosticarCuentaRemota, ErrorCuentaRemota, registrarVinculacion, reiniciarCursor } from './vinculacion';
import { sincronizarAhora } from './motor';

export type PasoUnion = 'servidor' | 'subiendo' | 'respaldo' | 'adoptando' | 'sincronizando';

export interface ResultadoUnion {
	subidos: number;
	/** Recursos locales que no se pudieron leer (por ejemplo, sin secreto en este equipo). */
	omitidos: number;
}

function aad(resourceId: string, createdBy: string): Uint8Array {
	const bytes = new Uint8Array(32);
	bytes.set(uuidABytes(resourceId), 0);
	bytes.set(uuidABytes(createdBy), 16);
	return bytes;
}

interface RecursoLocalCrudo {
	id: string;
	created_by: string | null;
	resource_type_slug: string;
	metadata_ciphertext_b64: string;
	metadata_nonce_b64: string;
	folder_id?: string | null;
}

export async function unirConCuentaDelServidor(
	serverUrlCrudo: string,
	passphraseServidor: string,
	alAvanzar: (paso: PasoUnion) => void = () => {}
): Promise<ResultadoUnion> {
	const serverUrl = serverUrlCrudo.trim().replace(/\/+$/, '');
	const email = get(sesion).email;
	const userIdLocal = get(sesion).userId;
	const clavesLocales = get(clavesDesbloqueadas);
	if (!email || !userIdLocal || !clavesLocales) throw new Error('No hay una sesión desbloqueada.');
	const wasm = await cargarCrypto();

	// 1. Identidad del servidor.
	alAvanzar('servidor');
	const remotoAnonimo = clienteRemoto(serverUrl, null);
	let material: { encrypted_private_key_blob_b64: string; private_key_nonce_b64: string; kdf_salt_b64: string };
	try {
		material = await remotoAnonimo.post('/auth/key-material', { email });
	} catch (err) {
		throw new ErrorCuentaRemota(err instanceof TypeError ? { estado: 'sin_conexion' } : { estado: 'servidor_invalido' });
	}
	let abierta: { x25519Private: Uint8Array; ed25519Private: Uint8Array };
	try {
		abierta = await abrirClavePrivadaEnWorker(
			passphraseServidor,
			base64ABytes(material.kdf_salt_b64),
			base64ABytes(material.private_key_nonce_b64),
			base64ABytes(material.encrypted_private_key_blob_b64),
			new TextEncoder().encode(email)
		);
	} catch {
		throw new ErrorCuentaRemota({ estado: 'error', mensaje: 'La frase no corresponde a la cuenta de ese servidor.' });
	}
	const clavesServidor: ClavesDesbloqueadas = {
		x25519Private: abierta.x25519Private,
		ed25519Private: abierta.ed25519Private,
		x25519Public: wasm.clave_publica_x25519_de(abierta.x25519Private),
		ed25519Public: wasm.clave_publica_ed25519_de(abierta.ed25519Private)
	};
	const diagnostico = await diagnosticarCuentaRemota(serverUrl, email, clavesServidor);
	if (diagnostico.estado !== 'ok') throw new ErrorCuentaRemota(diagnostico);
	if (!diagnostico.userId) throw new ErrorCuentaRemota({ estado: 'servidor_invalido' });
	const userIdServidor = diagnostico.userId;
	const remoto = clienteRemoto(serverUrl, diagnostico.sessionId);

	// 2. Subir carpetas (padres primero) y recursos, re-cifrados para el servidor.
	alAvanzar('subiendo');
	const carpetas = await listarArbolCarpetas(clavesLocales);
	const pendientes = [...carpetas];
	const subidas = new Set<string>();
	while (pendientes.length > 0) {
		const i = pendientes.findIndex((c) => c.parentId === null || subidas.has(c.parentId));
		if (i < 0) break; // padre ausente: no debería pasar, se dejan en la raíz por el sync
		const [c] = pendientes.splice(i, 1);
		const nombreSellado = wasm.sellar_para(clavesServidor.x25519Public, new TextEncoder().encode(c.nombre));
		try {
			await remoto.post('/folders', {
				id: c.id,
				name_ciphertext_b64: bytesABase64(nombreSellado),
				name_nonce_b64: '',
				parent_folder_id: c.parentId
			});
		} catch (err) {
			if (!(err instanceof RemoteApiError && err.status === 409)) throw err; // 409: ya estaba (reintento)
		}
		subidas.add(c.id);
	}

	const recursos = await api.get<RecursoLocalCrudo[]>('/resources');
	let subidos = 0;
	let omitidos = 0;
	for (const r of recursos) {
		let secreto: { sealed_dek_b64: string; secret_ciphertext_b64: string; secret_nonce_b64: string };
		try {
			secreto = await api.get(`/resources/${r.id}/secret`);
		} catch (err) {
			if (err instanceof ApiError && err.status === 404) {
				omitidos++;
				continue;
			}
			throw err;
		}
		const creador = r.created_by ?? userIdLocal;
		const dekLocal = wasm.abrir_sellado(clavesLocales.x25519Private, base64ABytes(secreto.sealed_dek_b64));
		const metadata = wasm.descifrar_aead(dekLocal, base64ABytes(r.metadata_nonce_b64), base64ABytes(r.metadata_ciphertext_b64), aad(r.id, creador));
		const contenido = wasm.descifrar_aead(dekLocal, base64ABytes(secreto.secret_nonce_b64), base64ABytes(secreto.secret_ciphertext_b64), aad(r.id, creador));

		const dek = wasm.generar_dek();
		const aadServidor = aad(r.id, userIdServidor);
		const metadataCifrada = wasm.cifrar_aead(dek, metadata, aadServidor);
		const secretoCifrado = wasm.cifrar_aead(dek, contenido, aadServidor);
		const cuerpo = {
			id: r.id,
			resource_type_slug: r.resource_type_slug,
			metadata_ciphertext_b64: bytesABase64(metadataCifrada.ciphertext),
			metadata_nonce_b64: bytesABase64(metadataCifrada.nonce),
			sealed_dek_b64: bytesABase64(wasm.sellar_para(clavesServidor.x25519Public, dek)),
			secret_ciphertext_b64: bytesABase64(secretoCifrado.ciphertext),
			secret_nonce_b64: bytesABase64(secretoCifrado.nonce)
		};
		try {
			await remoto.post('/resources', cuerpo);
		} catch (err) {
			// 409: ya estaba en el servidor (un intento anterior que se cortó): se deja.
			if (!(err instanceof RemoteApiError && err.status === 409)) throw err;
		}
		if (r.folder_id && subidas.has(r.folder_id)) {
			await remoto.put(`/resources/${r.id}/move`, { folder_id: r.folder_id });
		}
		subidos++;
	}

	// 3. Copia de seguridad local antes de tocar la identidad.
	alAvanzar('respaldo');
	await api.post('/vault/backups');

	// 4. La identidad local pasa a ser la del servidor.
	alAvanzar('adoptando');
	let displayName = email;
	try {
		displayName = (await remoto.get<{ display_name: string }>('/me')).display_name || email;
	} catch {
		// cosmético
	}
	await api.post('/auth/adoptar-identidad', {
		email,
		display_name: displayName,
		public_key_x25519_b64: bytesABase64(clavesServidor.x25519Public),
		public_key_ed25519_b64: bytesABase64(clavesServidor.ed25519Public),
		encrypted_private_key_blob_b64: material.encrypted_private_key_blob_b64,
		private_key_nonce_b64: material.private_key_nonce_b64,
		kdf_salt_b64: material.kdf_salt_b64,
		user_id: userIdServidor
	});
	registrarVinculacion(serverUrl, email);
	reiniciarCursor(email);
	// El desbloqueo guardado en el llavero tenía la frase vieja.
	await desactivarLlavero(email).catch(() => {});

	// 5. Entrar con la frase del servidor y traer todo.
	alAvanzar('sincronizando');
	const login = await iniciarSesion(email, passphraseServidor);
	if (login.estado !== 'completo' || !login.claves) {
		throw new Error('La cuenta se unió, pero no se pudo volver a entrar. Cerrá sesión y entrá con la frase del servidor.');
	}
	sesion.set({ sessionId: login.sessionId ?? null, userId: login.userId ?? null, email });
	clavesDesbloqueadas.set(login.claves);
	try {
		await sincronizarAhora();
	} catch {
		// El sync automático lo reintenta.
	}
	return { subidos, omitidos };
}
