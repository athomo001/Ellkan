// Autor: Athan Espinoza

// Controller de autofill — valida la forma del pedido y delega al Service
// (spec 06 §2). Revelar el secreto para rellenar reusa `VAULT_REVELAR_SECRETO`
// tal cual (mismo route, mismo Controller que usa Quick Access) — no hace
// falta un segundo camino para lo mismo.

import { AutofillService, type CoincidenciaAutofill } from '../services/autofill-service';

export const AutofillController = {
	async buscarCoincidencias(payload: unknown): Promise<CoincidenciaAutofill[]> {
		const p = payload as { hostname?: unknown } | undefined;
		if (typeof p?.hostname !== 'string' || !p.hostname) throw new Error('falta hostname');
		return AutofillService.buscarCoincidencias(p.hostname);
	}
};
