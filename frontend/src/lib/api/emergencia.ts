// Autor: Athan Espinoza

// F-36 (pendiente #131): acceso de emergencia entre personas de la misma
// instancia. El servidor nunca ve el material en claro: lo sella el titular
// para la clave pública del contacto (`crypto/emergencia.ts`).

import { api } from './client';

export interface PersonaEmergencia {
	/** Vacíos cuando la persona es uno mismo. */
	email: string;
	display_name: string;
}

export type NivelEmergencia = 'view' | 'takeover';

export interface AccesoEmergencia {
	id: string;
	granter_id: string;
	grantee_id: string;
	granter: PersonaEmergencia;
	grantee: PersonaEmergencia;
	access_level: NivelEmergencia;
	wait_time_days: number;
	/** `invited` hasta que el contacto acepta. */
	status: 'invited' | 'accepted' | 'confirmed';
	/** Última solicitud: `pending`, `approved`, `rejected` o `granted_by_timeout`. */
	request_status: string | null;
	/** Sólo para el contacto, y sólo con el acceso concedido. */
	sealed_material_b64: string | null;
	created_at: string;
}

/** F-36 (#134): un recurso de la bóveda del titular, opaco. */
export interface RecursoTitularCrudo {
	id: string;
	created_by: string | null;
	resource_type_slug: string;
	metadata_ciphertext_b64: string;
	metadata_nonce_b64: string;
	metadata_key_type: 'user_key' | 'shared_key';
	metadata_key_id: string | null;
	metadata_sealed_key_b64: string | null;
	sealed_dek_b64: string;
	secret_ciphertext_b64: string;
	secret_nonce_b64: string;
	updated_at: string;
}

export interface BovedaTitularCruda {
	granter_id: string;
	granter: PersonaEmergencia;
	access_level: NivelEmergencia;
	sealed_material_b64: string;
	resources: RecursoTitularCrudo[];
}

export const emergenciaApi = {
	listar: () => api.get<AccesoEmergencia[]>('/me/emergency-access'),
	designar: (cuerpo: { grantee_id: string; access_level: NivelEmergencia; sealed_material_b64: string; wait_time_days: number }) =>
		api.post<AccesoEmergencia>('/me/emergency-access', cuerpo),
	aceptar: (id: string) => api.post<void>(`/me/emergency-access/${id}/accept`),
	revocar: (id: string) => api.delete<void>(`/me/emergency-access/${id}`),
	solicitar: (id: string) => api.post<void>(`/me/emergency-access/${id}/request`),
	aprobar: (id: string) => api.post<void>(`/me/emergency-access/${id}/approve`),
	rechazar: (id: string) => api.post<void>(`/me/emergency-access/${id}/reject`),
	/** Sólo lectura; cada llamada queda en la auditoría. */
	boveda: (id: string) => api.get<BovedaTitularCruda>(`/me/emergency-access/${id}/vault`),
	/** Nivel `takeover`: mismo cuerpo que `POST /me/change-passphrase`. */
	takeover: (id: string, cuerpo: Record<string, unknown>) => api.post<void>(`/me/emergency-access/${id}/takeover`, cuerpo)
};
