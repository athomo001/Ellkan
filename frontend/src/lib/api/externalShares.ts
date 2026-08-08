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

export const externalSharesApi = {
	obtener: (id: string) => api.get<ExternalShareContenido>(`/external-shares/${id}`),
	crear: (body: {
		ciphertext_b64: string;
		password_protected: boolean;
		password_salt_b64?: string;
		max_views?: number;
		expires_in_hours: number;
	}) => api.post<ExternalShareCreado>('/external-shares', body)
};
