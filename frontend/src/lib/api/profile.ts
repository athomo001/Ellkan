// Autor: Athan Espinoza

// F-01: wrapper de `/me` (perfil de sólo lectura) y `/me/avatar`.

import { get } from 'svelte/store';
import { api } from './client';
import { sesion } from '$lib/state/session';

export interface Perfil {
	email: string;
	display_name: string;
	role: string;
	created_at: string;
	updated_at: string;
	keys_created_at: string;
}

export const perfilApi = {
	obtener: () => api.get<Perfil>('/me')
};

/**
 * `GET /me/avatar` devuelve bytes de imagen, no JSON — igual criterio que
 * `descargarExport` (`$lib/api/admin.ts`): un `<img src="/me/avatar">` no
 * manda el header `Authorization`, así que hay que pedirlo con `fetch`
 * autenticado a mano y armar un blob URL. `null` si el usuario no tiene
 * avatar cargado (`404`) — nunca una excepción para ese caso, es un estado
 * normal, no un error.
 */
export async function obtenerAvatarUrl(): Promise<string | null> {
	const sessionId = get(sesion).sessionId;
	const resp = await fetch('/me/avatar', { headers: sessionId ? { Authorization: `Bearer ${sessionId}` } : {} });
	if (resp.status === 404) return null;
	if (!resp.ok) throw new Error(`avatar: ${resp.status}`);
	const blob = await resp.blob();
	return URL.createObjectURL(blob);
}

export const avatarApi = {
	actualizar: (avatarB64: string, contentType: string) =>
		api.put<void>('/me/avatar', { avatar_b64: avatarB64, content_type: contentType }),
	eliminar: () => api.delete<void>('/me/avatar')
};
