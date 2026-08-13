// Autor: Athan Espinoza

// Controller de Quick Access — valida la forma del pedido y delega al
// Service (spec 06 §2). Sin lógica de negocio acá.

import { VaultService, type ItemVault } from '../services/vault-service';

function validarResourceId(payload: unknown): string {
	const p = payload as { resourceId?: unknown } | undefined;
	if (typeof p?.resourceId !== 'string' || !p.resourceId) throw new Error('falta resourceId');
	return p.resourceId;
}

export const VaultController = {
	async listar(): Promise<ItemVault[]> {
		return VaultService.listar();
	},

	async revelarPassword(payload: unknown): Promise<{ password: string }> {
		const resourceId = validarResourceId(payload);
		const password = await VaultService.revelarPassword(resourceId);
		return { password };
	}
};
