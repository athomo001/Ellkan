// Autor: Athan Espinoza

// Controller de autenticación — valida la forma del pedido y delega al
// Service (spec 06 §2). Sin lógica de negocio acá.

import { AuthService, type ResultadoLogin, type EstadoSesionActual } from '../services/auth-service';

interface PedidoLogin {
	serverUrl: string;
	email: string;
	passphrase: string;
}
interface PedidoVerificarDispositivo {
	serverUrl: string;
	deviceChallengeId: string;
	codigo: string;
}

function validarPedidoLogin(payload: unknown): PedidoLogin {
	const p = payload as Partial<PedidoLogin> | undefined;
	if (!p?.serverUrl || !p.email || !p.passphrase) {
		throw new Error('faltan datos: servidor, email y passphrase son obligatorios');
	}
	return { serverUrl: p.serverUrl, email: p.email, passphrase: p.passphrase };
}

function validarPedidoVerificarDispositivo(payload: unknown): PedidoVerificarDispositivo {
	const p = payload as Partial<PedidoVerificarDispositivo> | undefined;
	if (!p?.serverUrl || !p.deviceChallengeId || !p.codigo) {
		throw new Error('faltan datos: servidor, deviceChallengeId y código son obligatorios');
	}
	return { serverUrl: p.serverUrl, deviceChallengeId: p.deviceChallengeId, codigo: p.codigo };
}

export const AuthController = {
	async login(payload: unknown): Promise<ResultadoLogin> {
		const { serverUrl, email, passphrase } = validarPedidoLogin(payload);
		return AuthService.login(serverUrl.replace(/\/+$/, ''), email, passphrase);
	},

	async verificarDispositivo(payload: unknown): Promise<{ estado: string; sessionId?: string }> {
		const { serverUrl, deviceChallengeId, codigo } = validarPedidoVerificarDispositivo(payload);
		return AuthService.verificarDispositivo(serverUrl.replace(/\/+$/, ''), deviceChallengeId, codigo);
	},

	async estadoSesion(): Promise<EstadoSesionActual | null> {
		return AuthService.estadoSesion();
	},

	async estadoPendienteDispositivo() {
		return AuthService.estadoPendienteDispositivo();
	},

	async cancelarPendienteDispositivo(): Promise<void> {
		return AuthService.cancelarPendienteDispositivo();
	},

	async logout(): Promise<void> {
		return AuthService.logout();
	}
};
