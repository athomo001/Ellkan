// Autor: Athan Espinoza

// Controller de autenticación — valida la forma del pedido y delega al
// Service (spec 06 §2). Sin lógica de negocio acá.

import { AuthService, type ResultadoLogin, type EstadoSesionActual } from '../services/auth-service';

interface PedidoLogin {
	serverUrl: string;
	email: string;
	passphrase: string;
	forceMfa?: boolean;
}
interface PedidoVerificarDispositivo {
	serverUrl: string;
	deviceChallengeId: string;
	codigo: string;
}
interface PedidoVerificarMfa {
	serverUrl: string;
	sessionIdParcial: string;
	codigo: string;
}

function validarPedidoLogin(payload: unknown): PedidoLogin {
	const p = payload as Partial<PedidoLogin> | undefined;
	if (!p?.serverUrl || !p.email || !p.passphrase) {
		throw new Error('faltan datos: servidor, email y passphrase son obligatorios');
	}
	return { serverUrl: p.serverUrl, email: p.email, passphrase: p.passphrase, forceMfa: p.forceMfa };
}

function validarPedidoVerificarMfa(payload: unknown): PedidoVerificarMfa {
	const p = payload as Partial<PedidoVerificarMfa> | undefined;
	if (!p?.serverUrl || !p.sessionIdParcial || !p.codigo) {
		throw new Error('faltan datos: servidor, sessionIdParcial y código son obligatorios');
	}
	return { serverUrl: p.serverUrl, sessionIdParcial: p.sessionIdParcial, codigo: p.codigo };
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
		const { serverUrl, email, passphrase, forceMfa } = validarPedidoLogin(payload);
		return AuthService.login(serverUrl.replace(/\/+$/, ''), email, passphrase, forceMfa);
	},

	async verificarDispositivo(payload: unknown): Promise<{ estado: string; sessionId?: string }> {
		const { serverUrl, deviceChallengeId, codigo } = validarPedidoVerificarDispositivo(payload);
		return AuthService.verificarDispositivo(serverUrl.replace(/\/+$/, ''), deviceChallengeId, codigo);
	},

	async verificarMfa(payload: unknown): Promise<void> {
		const { serverUrl, sessionIdParcial, codigo } = validarPedidoVerificarMfa(payload);
		return AuthService.verificarMfa(serverUrl.replace(/\/+$/, ''), sessionIdParcial, codigo);
	},

	async estadoSesion(): Promise<EstadoSesionActual | null> {
		return AuthService.estadoSesion();
	},

	async estadoCuenta() {
		return AuthService.estadoCuenta();
	},

	async limpiarMarcaDeBloqueo(): Promise<void> {
		return AuthService.limpiarMarcaDeBloqueo();
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
