// Autor: Athan Espinoza

// F-27: wrappers de `/export-policy`, `/admin/export-policy` y
// `/export-events` — mismo patrón `{obtener, actualizar}` que el resto de
// políticas en `admin.ts`.

import { api } from './client';

export interface ExportPolicy {
	export_enabled: boolean;
	allowed_formats: string[];
	import_enabled: boolean;
}

export const exportPolicyApi = {
	/** Cualquier usuario autenticado — necesita saberlo antes de intentar exportar/importar. */
	obtener: () => api.get<ExportPolicy>('/export-policy')
};

export const adminExportPolicyApi = {
	/** Sólo admin. Un `200` acá también sirve como señal de que el usuario tiene la excepción de rol sobre `export_enabled` (mismo criterio que el guard de `(app)/admin/+layout.svelte`). */
	obtener: () => api.get<ExportPolicy>('/admin/export-policy'),
	actualizar: (p: ExportPolicy) => api.put<ExportPolicy>('/admin/export-policy', p)
};

export interface ExportEvent {
	event_type: 'export' | 'import';
	format: 'kdbx' | 'csv' | 'cxf';
	resource_count: number;
}

export const exportEventsApi = {
	/** Se llama antes de generar el archivo (export) o crear los recursos (import) — si rechaza, no se hace nada más. */
	reportar: (evento: ExportEvent) => api.post<void>('/export-events', evento)
};
