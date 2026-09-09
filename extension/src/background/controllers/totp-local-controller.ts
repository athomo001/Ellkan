// Autor: Athan Espinoza

// Controller de F-38 (desbloqueo rápido local con TOTP) — valida la forma
// del pedido y delega al Service (spec 06 §2). Sin lógica de negocio acá.

import { TotpLocalService } from '../services/totp-local-service';
import type { ResultadoLogin } from '../services/auth-service';

function codigoValido(v: unknown): string {
	if (typeof v !== 'string' || !/^\d{6}$/.test(v.trim())) throw new Error('el código debe tener 6 dígitos');
	return v.trim();
}

export const TotpLocalController = {
	async estado(): Promise<{ activo: boolean }> {
		return TotpLocalService.estado();
	},

	async generarSetup(): Promise<{ secretoB64: string; secretoBase32: string; otpauthUri: string }> {
		return TotpLocalService.generarSetup();
	},

	async confirmar(payload: unknown): Promise<{ ok: true }> {
		const p = payload as { secretoB64?: unknown; codigo?: unknown; passphrase?: unknown } | undefined;
		if (typeof p?.secretoB64 !== 'string' || !p.secretoB64) throw new Error('falta el secreto del setup');
		if (typeof p?.passphrase !== 'string' || !p.passphrase) throw new Error('falta la Contraseña Master');
		await TotpLocalService.confirmar(p.secretoB64, codigoValido(p.codigo), p.passphrase);
		return { ok: true };
	},

	async desactivar(): Promise<{ ok: true }> {
		await TotpLocalService.desactivar();
		return { ok: true };
	},

	async desbloquear(payload: unknown): Promise<ResultadoLogin> {
		const p = payload as { codigo?: unknown } | undefined;
		return TotpLocalService.desbloquear(codigoValido(p?.codigo));
	}
};
