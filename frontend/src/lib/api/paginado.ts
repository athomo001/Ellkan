// Autor: Athan Espinoza

// QA-12: `GET /resources` paginado por cursor. Con `?limit=` el servidor
// devuelve una página y, si quedan más, la cabecera `X-Ellkan-Next-Cursor`;
// la siguiente se pide con `&after=<cursor>`. El fin lo marca la AUSENCIA de
// la cabecera, nunca una página corta: un servidor anterior a QA-12 ignora
// `limit`, devuelve la lista entera y no manda la cabecera — el bucle hace
// un solo pedido y sigue funcionando.

export const LIMITE_PAGINA = 500;
export const CABECERA_CURSOR = 'x-ellkan-next-cursor';

/** Tope de pedidos: una bóveda de 5 millones de recursos; más es un bucle. */
const MAX_PAGINAS = 10_000;

export interface Pagina<T> {
	cuerpo: T[];
	cabeceras: Headers;
}

/** Junta todas las páginas de `ruta` (que puede traer ya su `?`). */
export async function traerTodasLasPaginas<T>(ruta: string, pedirPagina: (ruta: string) => Promise<Pagina<T>>): Promise<T[]> {
	const separador = ruta.includes('?') ? '&' : '?';
	const base = `${ruta}${separador}limit=${LIMITE_PAGINA}`;
	const todos: T[] = [];
	let cursor: string | null = null;
	for (let i = 0; i < MAX_PAGINAS; i++) {
		const pagina = await pedirPagina(cursor ? `${base}&after=${encodeURIComponent(cursor)}` : base);
		todos.push(...pagina.cuerpo);
		const siguiente = pagina.cabeceras.get(CABECERA_CURSOR);
		// Sin cursor, o el mismo de antes (un servidor roto): terminó.
		if (!siguiente || siguiente === cursor) return todos;
		cursor = siguiente;
	}
	throw new Error(`la lista de ${ruta} no terminó después de ${MAX_PAGINAS} páginas`);
}
