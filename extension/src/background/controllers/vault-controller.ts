// Autor: Athan Espinoza

// Controller de Quick Access — valida la forma del pedido y delega al
// Service (spec 06 §2). Sin lógica de negocio acá.

import { VaultService, type ItemVault, type SecretoRevelado, type DatosRecurso } from '../services/vault-service';

function validarResourceId(payload: unknown): string {
	const p = payload as { resourceId?: unknown } | undefined;
	if (typeof p?.resourceId !== 'string' || !p.resourceId) throw new Error('falta resourceId');
	return p.resourceId;
}

function validarDatosRecurso(payload: unknown): DatosRecurso {
	const p = payload as { datos?: Partial<DatosRecurso> } | undefined;
	const d = p?.datos;
	if (!d?.nombre || !d.password) throw new Error('faltan datos: nombre y contraseña son obligatorios');
	return {
		tipo: d.tipo,
		nombre: d.nombre,
		usuario: d.usuario ?? '',
		uri: d.uri ?? '',
		password: d.password,
		notas: d.notas ?? '',
		totpSecretBase32: d.totpSecretBase32
	};
}

export const VaultController = {
	async listar(): Promise<ItemVault[]> {
		return VaultService.listar();
	},

	async revelarSecreto(payload: unknown): Promise<SecretoRevelado> {
		const resourceId = validarResourceId(payload);
		return VaultService.revelarSecreto(resourceId);
	},

	async crear(payload: unknown): Promise<void> {
		return VaultService.crear(validarDatosRecurso(payload));
	},

	async editar(payload: unknown): Promise<{ updatedAt: string }> {
		const p = payload as { item?: ItemVault } | undefined;
		if (!p?.item) throw new Error('falta el ítem a editar');
		return VaultService.editar(p.item, validarDatosRecurso(payload));
	}
};
