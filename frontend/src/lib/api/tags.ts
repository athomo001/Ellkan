// Autor: Athan Espinoza

// F-10: `tags.name` queda en claro por diseño (`02-modelo-de-datos.md`
// sección 7) — a diferencia de `carpetas.ts`, acá no hace falta ninguna
// crypto client-side, mismo criterio que `admin.ts` para datos no sensibles.

import { api } from './client';

export interface Tag {
	id: string;
	name: string;
	is_shared: boolean;
	created_by: string | null;
}

export const tagsApi = {
	listar: () => api.get<Tag[]>('/tags'),
	crear: (name: string, isShared: boolean) => api.post<Tag>('/tags', { id: crypto.randomUUID(), name, is_shared: isShared }),
	/**
	 * IDs de recursos con `tagId` — `GET /resources?tag_id=` ya devuelve el
	 * `RecursoResponse` completo (todavía cifrado), pero acá sólo interesa
	 * el `id` para intersectar contra la lista ya descifrada por
	 * `listarRecursos` (`recursos.ts`) — nunca se vuelve a descifrar nada.
	 */
	async idsConTag(tagId: string): Promise<string[]> {
		const recursos = await api.get<{ id: string }[]>(`/resources?tag_id=${tagId}`);
		return recursos.map((r) => r.id);
	},
	aplicar: (resourceId: string, tagId: string) => api.post<void>(`/resources/${resourceId}/tags/${tagId}`),
	quitar: (resourceId: string, tagId: string) => api.delete<void>(`/resources/${resourceId}/tags/${tagId}`)
};
