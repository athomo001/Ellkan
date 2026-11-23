// Autor: Athan Espinoza

// QA-32 (pendiente #117): mínimo privilegio por tipo de puerto. El content
// script se inyecta en cualquier página y en cualquier iframe
// (`<all_urls>`, `all_frames`): un bug suyo, o un renderer comprometido, no
// tiene que poder listar la bóveda, cerrar la sesión ni tocar el desbloqueo
// rápido. Sólo el popup (`QuickAccess`, verificado por `sender.id` en
// `PortManager`) tiene todas las rutas.

import type { WorkerName } from './types';

/** Lo único que puede pedir un content script. */
export const RUTAS_CONTENT: readonly string[] = ['AUTOFILL_BUSCAR', 'VAULT_REVELAR_SECRETO', 'VAULT_CREAR'];

export function rutaPermitida(worker: WorkerName, tipo: string): boolean {
	return worker === 'QuickAccess' || RUTAS_CONTENT.includes(tipo);
}

/**
 * La URL que cuenta para un content script. `sender.url` la pone el navegador
 * (la página no la puede falsificar) pero queda fija al conectar el puerto:
 * en una SPA que cambió de ruta con `pushState`, el path real es otro. El
 * origen, en cambio, no cambia sin recargar: se acepta el `href` que manda la
 * página sólo si es del mismo origen que el frame; si no, `sender.url`.
 */
export function hrefDelRemitente(pedido: unknown, urlRemitente: string | undefined): string | undefined {
	if (!urlRemitente) return undefined;
	try {
		if (typeof pedido === 'string' && new URL(pedido).origin === new URL(urlRemitente).origin) return pedido;
	} catch {
		// href ilegible: se usa el del navegador
	}
	return urlRemitente;
}

/**
 * Desde un content script, el secreto de un recurso sólo sale si ese recurso
 * coincide con la página real del frame que lo pide (`sender.url`, que pone
 * el navegador y la página no puede falsificar) — mismo matching que el
 * autofill. Un iframe de otro sitio dentro de la página del banco no puede
 * pedir la contraseña del banco.
 */
export async function revelarSiCorrespondeALaPagina<T>(
	resourceId: string,
	urlRemitente: string | undefined,
	buscarCoincidencias: (href: string) => Promise<{ id: string }[]>,
	revelar: (resourceId: string) => Promise<T>
): Promise<T> {
	if (!urlRemitente) throw new Error('no se puede verificar la página que pide el secreto');
	const coincidencias = await buscarCoincidencias(urlRemitente);
	if (!coincidencias.some((c) => c.id === resourceId)) throw new Error('ese recurso no corresponde a esta página');
	return revelar(resourceId);
}
