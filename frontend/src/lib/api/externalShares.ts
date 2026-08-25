// Autor: Athan Espinoza

// F-26: wrapper tipado de `/external-shares`. `obtener` pega contra el
// único endpoint sin sesión de toda la API — `api.get` igual funciona acá
// (no manda `Authorization` si no hay sesión activa en el store, y aunque
// la mandara el backend la ignora, no hay extractor de auth en ese handler).

import { api } from './client';

export interface ExternalShareContenido {
	ciphertext_b64: string;
	password_protected: boolean;
	password_salt_b64: string | null;
}

export interface ExternalShareCreado {
	id: string;
	max_views: number;
	expires_at: string;
}

export interface ExternalShareResumen {
	id: string;
	password_protected: boolean;
	max_views: number;
	view_count: number;
	expires_at: string;
	revoked_at: string | null;
	burned_at: string | null;
	created_at: string;
}

export interface ExternalSharePolicy {
	enabled: boolean;
	max_expiration_hours: number;
	require_password: boolean;
	/** A diferencia de `enabled`/`require_password`, `allow_file` no es una
	 * barrera técnica real — el .7z nunca toca el servidor, así que sólo
	 * controla qué botón muestra el Vault. */
	allow_link: boolean;
	allow_file: boolean;
}

export const adminExternalSharePolicyApi = {
	obtener: () => api.get<ExternalSharePolicy>('/admin/external-share-policy'),
	actualizar: (p: ExternalSharePolicy) => api.put<ExternalSharePolicy>('/admin/external-share-policy', p)
};

/** No-admin — el Vault la consulta para decidir si mostrar "Compartir
 * externo" y qué método(s) ofrecer, mismo patrón que `exportPolicyApi` vs
 * `adminExportPolicyApi`. */
export const externalSharePolicyApi = {
	obtener: () => api.get<ExternalSharePolicy>('/external-share-policy')
};

export const externalSharesApi = {
	obtener: (id: string) => api.get<ExternalShareContenido>(`/external-shares/${id}`),
	crear: (body: {
		ciphertext_b64: string;
		password_protected: boolean;
		password_salt_b64?: string;
		max_views?: number;
		expires_in_hours: number;
	}) => api.post<ExternalShareCreado>('/external-shares', body),
	listar: () => api.get<ExternalShareResumen[]>('/external-shares'),
	revocar: (id: string) => api.delete<void>(`/external-shares/${id}`)
};
