// Autor: Athan Espinoza

// QA-21: sesiones abiertas de la cuenta, para cerrar las que no son ésta.

import { api } from './client';

export interface SesionAbierta {
	id: string;
	/** "Chrome · Windows"; `null` si todavía no hizo ninguna solicitud. */
	dispositivo: string | null;
	creada: string;
	ultimo_uso: string | null;
	/** La sesión desde la que se consulta. */
	actual: boolean;
}

export const sesionesApi = {
	listar: () => api.get<SesionAbierta[]>('/me/sessions'),
	cerrar: (id: string) => api.delete<void>(`/me/sessions/${id}`),
	cerrarOtras: () => api.post<{ cerradas: number }>('/me/sessions/close-others')
};
