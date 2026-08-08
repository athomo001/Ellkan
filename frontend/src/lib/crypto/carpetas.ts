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
}

interface NodoArbolCrudo {
	folder_id: string;
	parent_folder_id: string | null;
	name_ciphertext_b64: string;
	name_nonce_b64: string;
}

export async function listarArbolCarpetas(claves: ClavesDesbloqueadas): Promise<NodoCarpeta[]> {
	const wasm = await cargarCrypto();
	const crudos = await api.get<NodoArbolCrudo[]>('/folders');
	return crudos.map((n) => {
		const bytes = wasm.abrir_sellado(claves.x25519Private, base64ABytes(n.name_ciphertext_b64));
		return { id: n.folder_id, parentId: n.parent_folder_id, nombre: new TextDecoder().decode(bytes) };
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
	return { id, parentId: parentFolderId, nombre };
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
