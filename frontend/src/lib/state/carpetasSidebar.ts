// Autor: Athan Espinoza

// Puente entre `vault/+page.svelte` (dueño real de los datos de carpetas) y
// `(app)/+layout.svelte` (el shell persistente, sin acceso directo a ese
// estado) — pedido explícito del usuario: el árbol de carpetas vive en la
// barra lateral fija, no como una columna más del grid del Vault, que en la
// ventana angosta del modo escritorio competía por espacio con la tabla de
// recursos. Sólo la página que tiene carpetas (Vault) escribe acá; el resto
// de las páginas la dejan en `null` y el layout no renderiza nada.

import { writable } from 'svelte/store';
import type { NodoCarpeta } from '$lib/crypto/carpetas';

export interface CarpetasSidebarProps {
	nodos: NodoCarpeta[];
	cargando: boolean;
	filtroActivo: string | null | undefined;
	onCrear?: (nombre: string, parentId: string | null) => void | Promise<void>;
	onMover?: (folderId: string, newParentId: string | null) => void | Promise<void>;
	onFiltrar?: (folderId: string) => void;
	onCompartir?: (folderId: string, nombre: string) => void | Promise<void>;
}

export const carpetasSidebar = writable<CarpetasSidebarProps | null>(null);
