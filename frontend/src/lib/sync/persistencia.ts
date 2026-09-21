// Autor: Athan Espinoza

// F-48: los 3 modos de persistencia de secretos por bóveda (spec/13 §8) —
// wrapper mínimo contra `GET/PUT /vault/persistence`, ya construido del lado
// del backend de escritorio (`app-escritorio/backend-desktop/router.rs`)
// pero sin ningún consumidor hasta este cambio.

import { api } from '$lib/api/client';

export type ModoPersistencia = 'full' | 'memory' | 'names_only';

interface PersistenciaCruda {
	mode: ModoPersistencia;
}

export async function obtenerPersistencia(): Promise<ModoPersistencia> {
	const resp = await api.get<PersistenciaCruda>('/vault/persistence');
	return resp.mode;
}

export async function cambiarPersistencia(modo: ModoPersistencia): Promise<ModoPersistencia> {
	const resp = await api.put<PersistenciaCruda>('/vault/persistence', { mode: modo });
	return resp.mode;
}
