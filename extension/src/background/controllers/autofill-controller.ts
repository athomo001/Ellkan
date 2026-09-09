// Autor: Athan Espinoza

// Controller de autofill — valida la forma del pedido y delega al Service
// (spec 06 §2). Revelar el secreto para rellenar reusa `VAULT_REVELAR_SECRETO`
// tal cual (mismo route, mismo Controller que usa Quick Access) — no hace
// falta un segundo camino para lo mismo.

import { AutofillService, type CoincidenciaAutofill } from '../services/autofill-service';

export const AutofillController = {
	async buscarCoincidencias(payload: unknown): Promise<CoincidenciaAutofill[]> {
		const p = payload as { href?: unknown; hostname?: unknown } | undefined;
		// `href` es la forma nueva (necesaria para la estrategia `exact`, que
		// compara el path). `hostname` se sigue aceptando por compatibilidad
		// con un content script viejo — se reconstruye un href https:// mínimo.
		let href: string | null = null;
		if (typeof p?.href === 'string' && p.href) href = p.href;
		else if (typeof p?.hostname === 'string' && p.hostname) href = `https://${p.hostname}/`;
		if (!href) throw new Error('falta href/hostname');
		return AutofillService.buscarCoincidencias(href);
	}
};
