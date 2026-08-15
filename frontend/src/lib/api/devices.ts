// Autor: Athan Espinoza

// F-37: dispositivos de confianza propios — el backend ya existía completo
// (`backend/src/devices/`) desde el cierre de Fase 1.2, nunca tuvo UI hasta
// ahora.

import { api } from './client';

export interface TrustedDevice {
	id: string;
	label: string | null;
	created_at: string;
	revoked_at: string | null;
}

export const devicesApi = {
	listar: () => api.get<TrustedDevice[]>('/me/devices'),
	revocar: (id: string) => api.delete<void>(`/me/devices/${id}`)
};
