// Autor: Athan Espinoza

// F-09: carpetas con vista por-usuario, sin sharing — el nombre se sella
// con la propia clave pública X25519 del usuario (mismo primitivo "sellar
// para uno mismo" que `crearRecurso` ya usa para `sealed_dek_b64` en
// `recursos.ts`), nunca con la `metadata_key` compartida: `folders.name_key_id`
// (la FK a `metadata_keys` que el schema declara, `backend/migrations/0005_folders.sql`)
// nunca se pobló en ningún endpoint real — `CrearCarpetaRequest`/`NodoArbolResponse`
// no lo tienen (`backend/src/folders/dto.rs`). Usar esa clave sin una forma
// de registrar qué versión se usó sería un gap real de re-key tras una
// rotación (F-33), no sólo un detalle cosmético — sellar al propio X25519
// no tiene ese problema: la misma clave privada de siempre alcanza para
// descifrar, sin importar rotaciones de metadata_key.
//
// `sellar_para` devuelve un blob combinado (clave efímera + nonce +
// ciphertext) — no separa en ciphertext/nonce como el DTO pide
// (`name_ciphertext_b64`/`name_nonce_b64`), así que el blob entero va en
// `name_ciphertext_b64` y `name_nonce_b64` viaja vacío: el backend nunca
// valida ni interpreta estos dos campos (`backend/src/folders/handlers.rs`/
// `repository.rs` — passthrough puro a `bytea not null`, un `bytea` vacío
// es un valor válido), sólo los guarda y los devuelve tal cual.

import { cargarCrypto } from './wasm';
import { bytesABase64, base64ABytes } from './b64';
import { api } from '$lib/api/client';
import type { ClavesDesbloqueadas } from '$lib/state/session';

export interface NodoCarpeta {
	id: string;
	parentId: string | null;
	nombre: string;
	/** 2026-08-11: `group_id` si la carpeta está compartida con un grupo
	 * entero — el Vault lo usa para ofrecer ceder/mantener al mover un
	 * recurso acá, y para saber que cualquier miembro puede agregar sin
	 * necesitar `update` individual. */
	groupId: string | null;
}

interface NodoArbolCrudo {
	folder_id: string;
	parent_folder_id: string | null;
	name_ciphertext_b64: string;
	name_nonce_b64: string;
	group_id?: string | null;
}

export async function listarArbolCarpetas(claves: ClavesDesbloqueadas): Promise<NodoCarpeta[]> {
	const wasm = await cargarCrypto();
	const crudos = await api.get<NodoArbolCrudo[]>('/folders');
	return crudos.map((n) => {
		const bytes = wasm.abrir_sellado(claves.x25519Private, base64ABytes(n.name_ciphertext_b64));
		return {
			id: n.folder_id,
			parentId: n.parent_folder_id,
			nombre: new TextDecoder().decode(bytes),
			groupId: n.group_id ?? null
		};
	});
}

export async function crearCarpeta(
	nombre: string,
	parentFolderId: string | null,
	claves: ClavesDesbloqueadas
): Promise<NodoCarpeta> {
	const wasm = await cargarCrypto();
	const id = crypto.randomUUID();
	const sellado = wasm.sellar_para(claves.x25519Public, new TextEncoder().encode(nombre));
	await api.post('/folders', {
		id,
		name_ciphertext_b64: bytesABase64(sellado),
		name_nonce_b64: '',
		parent_folder_id: parentFolderId
	});
	return { id, parentId: parentFolderId, nombre, groupId: null };
}

/**
 * Descendientes (directos + indirectos) de `folderId` dentro de `nodos` —
 * usado para no ofrecer como destino de "mover" a la propia carpeta ni a
 * ninguno de sus descendientes: `FolderService::mover`
 * (`backend/src/folders/service.rs`) sólo valida el caso inmediato
 * (`folder_id == new_parent_folder_id`), no ciclos más profundos — se
 * mitiga acá, del lado del cliente.
 */
export function descendientesDe(folderId: string, nodos: NodoCarpeta[]): Set<string> {
	const hijos = new Map<string, string[]>();
	for (const n of nodos) {
		if (n.parentId === null) continue;
		hijos.set(n.parentId, [...(hijos.get(n.parentId) ?? []), n.id]);
	}
	const resultado = new Set<string>();
	const pila = [...(hijos.get(folderId) ?? [])];
	while (pila.length) {
		const actual = pila.pop()!;
		if (resultado.has(actual)) continue;
		resultado.add(actual);
		pila.push(...(hijos.get(actual) ?? []));
	}
	return resultado;
}

export async function moverCarpeta(folderId: string, newParentFolderId: string | null): Promise<void> {
	await api.put(`/folders/${folderId}/move`, { new_parent_folder_id: newParentFolderId });
}

/** F-11: mueve un RECURSO a una carpeta (o `null` = raíz). Nunca comparte el
 * recurso — moverlo a una carpeta ya compartida no le da acceso a nadie más,
 * eso sigue siendo `compartirRecurso` aparte (zero-knowledge: el servidor no
 * puede otorgar acceso a un secreto cifrado). */
export async function moverRecursoACarpeta(resourceId: string, folderId: string | null): Promise<void> {
	await api.put(`/resources/${resourceId}/move`, { folder_id: folderId });
}

/**
 * F-11: comparte una carpeta con otro usuario (por email) — exige `owner`
 * sobre ella server-side. Resella el nombre ya descifrado (`nombre`, mismo
 * texto que `listarArbolCarpetas` ya devuelve) contra la clave pública del
 * destinatario, mismo patrón que `compartirRecurso` en `recursos.ts`.
 */
export async function compartirCarpeta(
	folderId: string,
	nombre: string,
	emailDestinatario: string,
	nivel: 'read' | 'update' | 'owner'
): Promise<void> {
	const wasm = await cargarCrypto();
	const destinatario = await api.get<{ user_id: string; public_key_x25519_b64: string }>(
		`/users/${encodeURIComponent(emailDestinatario)}/public-key`
	);
	const sellado = wasm.sellar_para(base64ABytes(destinatario.public_key_x25519_b64), new TextEncoder().encode(nombre));

	await api.post(`/folders/${folderId}/share`, {
		grantee_type: 'user',
		grantee_id: destinatario.user_id,
		level: nivel,
		name_ciphertext_b64: bytesABase64(sellado),
		name_nonce_b64: ''
	});
}

/** 2026-08-11: resuelve la clave pública X25519 actual de cada miembro de
 * un grupo — usado tanto para compartir una carpeta con el grupo entero
 * como para "ceder" un recurso ya movido a una carpeta de grupo
 * (`compartirRecursosEnLote` en `recursos.ts`, que ya sabe sellar un DEK
 * por-destinatario, sólo necesita esta lista). Grupos chicos, no vale la
 * pena un endpoint bulk de public-keys sólo para esto. */
export async function resolverMiembrosConClave(
	miembros: { userId: string; email: string }[]
): Promise<{ userId: string; publicKeyX25519B64: string }[]> {
	return Promise.all(
		miembros.map(async (m) => {
			const destinatario = await api.get<{ public_key_x25519_b64: string }>(
				`/users/${encodeURIComponent(m.email)}/public-key`
			);
			return { userId: m.userId, publicKeyX25519B64: destinatario.public_key_x25519_b64 };
		})
	);
}

/**
 * 2026-08-11: comparte una carpeta con un GRUPO entero — exige ser admin de
 * grupo/organización server-side (`FolderService::verificar_puede_compartir`).
 * Resella el nombre para CADA miembro actual del grupo (mismo motivo
 * zero-knowledge de siempre: el servidor no puede resellar algo que no
 * puede leer) — grupos chicos, no vale la pena un endpoint bulk de
 * public-keys para esto.
 */
export async function compartirCarpetaConGrupo(
	folderId: string,
	nombre: string,
	groupId: string,
	miembros: { userId: string; email: string }[],
	nivel: 'read' | 'update' | 'owner'
): Promise<void> {
	const wasm = await cargarCrypto();
	const conClave = await resolverMiembrosConClave(miembros);
	const memberEnvelopes = conClave.map((m) => {
		const sellado = wasm.sellar_para(base64ABytes(m.publicKeyX25519B64), new TextEncoder().encode(nombre));
		return { user_id: m.userId, name_ciphertext_b64: bytesABase64(sellado), name_nonce_b64: '' };
	});

	await api.post(`/folders/${folderId}/share`, {
		grantee_type: 'group',
		grantee_id: groupId,
		level: nivel,
		member_envelopes: memberEnvelopes
	});
}
