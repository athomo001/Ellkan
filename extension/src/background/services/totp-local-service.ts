// Autor: Athan Espinoza

// F-38: desbloqueo rápido local con TOTP en la extensión — "algo que tenés"
// en vez de "algo que sabés", opt-in por dispositivo, 100% client-side
// (nunca valida contra el backend). Mismo criterio criptográfico que
// `frontend/src/lib/crypto/totp-local.ts`: la passphrase se envuelve con una
// clave derivada del secreto TOTP, y ese secreto a su vez se cifra con una
// `CryptoKey` AES-GCM **no-extraíble** de IndexedDB por dispositivo (fix de
// H-01, auditoría 2026-08-12: un volcado pasivo de storage ya no alcanza
// para reconstruir el secreto ni calcular un código offline).
//
// Diferencias con la web, deliberadas:
//  - `storage.local` en vez de `localStorage`.
//  - Toda la crypto corre en el service worker (el popup nunca ve la
//    passphrase en claro) — mismo criterio que el resto de la extensión.
//  - El enrolamiento pide la passphrase actual porque la extensión NO la
//    cachea (guarda las claves ya derivadas en `storage.session`, no la
//    passphrase — ver `auth-service.ts`).
//  - `desbloquear()` reconstruye la passphrase y corre el login real
//    completo (`AuthService.login`) — F-38 no se salta ningún paso, sólo
//    evita que el usuario tenga que tipear la Contraseña Master.

import { cargarCrypto } from '../wasm';
import { bytesABase64, base64ABytes } from '../../../../frontend/src/lib/crypto/b64';
import { base32Codificar } from '../../../../frontend/src/lib/crypto/base32';
import {
	obtenerClaveDeDispositivo,
	borrarClaveDeDispositivo
} from '../../../../frontend/src/lib/crypto/device-key';
import { CuentaStorage } from '../storage/cuenta-storage';
import { BrowserApi } from '../../browser-api';
import { AuthService, type ResultadoLogin } from './auth-service';

interface EstadoLocalTotp {
	/** Secreto TOTP cifrado con la clave de dispositivo, nunca en claro. */
	secretoCifradoB64: string;
	secretoIvB64: string;
	/** Passphrase envuelta con la clave derivada del secreto TOTP. */
	cipherB64: string;
	nonceB64: string;
}

export interface EstadoBackoff {
	fallosConsecutivos: number;
	bloqueadoHastaMs: number | null;
}

const CLAVE_ESTADO = 'ellkan.totp-local';
const CLAVE_BACKOFF = 'ellkan.totp-local-backoff';
const NOMBRE_CLAVE_DISP = 'totp-local';
/** 3 fallos consecutivos → 30s de bloqueo, igual que `ControlDeIntentos` del
 * lado Rust y que la web. */
export const INTENTOS_ANTES_DE_BLOQUEAR = 3;
export const BLOQUEO_MS = 30_000;

function aad(email: string): Uint8Array {
	return new TextEncoder().encode(`totp-local:${email}`);
}

async function leerEstado(): Promise<EstadoLocalTotp | null> {
	const r = await BrowserApi.storageLocalGet<Record<string, EstadoLocalTotp>>(CLAVE_ESTADO);
	return r[CLAVE_ESTADO] ?? null;
}

async function leerBackoff(): Promise<EstadoBackoff> {
	const r = await BrowserApi.storageLocalGet<Record<string, EstadoBackoff>>(CLAVE_BACKOFF);
	return r[CLAVE_BACKOFF] ?? { fallosConsecutivos: 0, bloqueadoHastaMs: null };
}

async function guardarBackoff(e: EstadoBackoff): Promise<void> {
	await BrowserApi.storageLocalSet({ [CLAVE_BACKOFF]: e });
}

/**
 * Decisión pura del backoff tras un intento (self-check en `self-check.ts`):
 * dado el estado previo y si el código fue válido, devuelve el estado nuevo
 * y si hay que abortar por bloqueo activo.
 */
export function siguienteBackoff(
	previo: EstadoBackoff,
	valido: boolean,
	ahoraMs: number
): { bloqueadoSegundos: number | null; nuevo: EstadoBackoff } {
	if (previo.bloqueadoHastaMs && ahoraMs < previo.bloqueadoHastaMs) {
		return { bloqueadoSegundos: Math.ceil((previo.bloqueadoHastaMs - ahoraMs) / 1000), nuevo: previo };
	}
	if (valido) return { bloqueadoSegundos: null, nuevo: { fallosConsecutivos: 0, bloqueadoHastaMs: null } };
	const fallos = previo.fallosConsecutivos + 1;
	return {
		bloqueadoSegundos: null,
		nuevo: {
			fallosConsecutivos: fallos,
			bloqueadoHastaMs: fallos >= INTENTOS_ANTES_DE_BLOQUEAR ? ahoraMs + BLOQUEO_MS : null
		}
	};
}

async function cuentaOTirar(): Promise<{ serverUrl: string; email: string }> {
	const c = await CuentaStorage.leer();
	if (!c) throw new Error('No hay una cuenta configurada en este dispositivo.');
	return { serverUrl: c.server_url, email: c.email };
}

export const TotpLocalService = {
	async estado(): Promise<{ activo: boolean }> {
		return { activo: (await leerEstado()) !== null };
	},

	/** Genera un secreto nuevo (nunca reusa el de F-14) + la URI otpauth para
	 * el QR. No lo activa: hace falta `confirmar()` con un código y la
	 * passphrase actual. El secreto viaja al popup sólo para mostrar el
	 * QR/base32 durante el setup — se descarta apenas se confirma. */
	async generarSetup(): Promise<{ secretoB64: string; secretoBase32: string; otpauthUri: string }> {
		const { email } = await cuentaOTirar();
		const wasm = await cargarCrypto();
		const secreto = wasm.totp_generar_secreto();
		const secretoBase32 = base32Codificar(secreto);
		const otpauthUri = `otpauth://totp/Ellkan%20%28local%29:${encodeURIComponent(email)}?secret=${secretoBase32}&issuer=Ellkan%20%28local%29&algorithm=SHA1&digits=6&period=30`;
		return { secretoB64: bytesABase64(secreto), secretoBase32, otpauthUri };
	},

	/** Confirma el setup: verifica el código contra el secreto recién
	 * generado (no queda activo sin probar que el usuario lo agregó de
	 * verdad a una app) y, si es válido, envuelve la passphrase y persiste el
	 * estado en este dispositivo. */
	async confirmar(secretoB64: string, codigo: string, passphrase: string): Promise<void> {
		const { email } = await cuentaOTirar();
		if (!passphrase) throw new Error('Falta la Contraseña Master.');
		const wasm = await cargarCrypto();
		const secreto = base64ABytes(secretoB64);
		const ahora = Math.floor(Date.now() / 1000);
		if (!wasm.totp_verificar(secreto, Number(codigo), BigInt(ahora))) throw new Error('Código incorrecto.');

		const cifrado = wasm.totp_envolver_passphrase(secreto, passphrase, aad(email));
		const claveDisp = await obtenerClaveDeDispositivo(NOMBRE_CLAVE_DISP);
		const iv = crypto.getRandomValues(new Uint8Array(12));
		const secretoCifrado = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, claveDisp, secreto as BufferSource);

		await BrowserApi.storageLocalSet({
			[CLAVE_ESTADO]: {
				secretoCifradoB64: bytesABase64(new Uint8Array(secretoCifrado)),
				secretoIvB64: bytesABase64(iv),
				cipherB64: bytesABase64(cifrado.ciphertext),
				nonceB64: bytesABase64(cifrado.nonce)
			} satisfies EstadoLocalTotp
		});
		await BrowserApi.storageLocalRemove(CLAVE_BACKOFF);
	},

	async desactivar(): Promise<void> {
		await BrowserApi.storageLocalRemove(CLAVE_ESTADO);
		await BrowserApi.storageLocalRemove(CLAVE_BACKOFF);
		await borrarClaveDeDispositivo(NOMBRE_CLAVE_DISP);
	},

	/** Desbloquea con un código de 6 dígitos: verifica (con backoff),
	 * reconstruye la passphrase y corre el login real. Devuelve lo mismo que
	 * `AUTH_LOGIN` — el popup lo maneja con el mismo `manejarResultadoLogin`. */
	async desbloquear(codigo: string): Promise<ResultadoLogin> {
		const estado = await leerEstado();
		if (!estado) throw new Error('El desbloqueo rápido no está activo en este dispositivo.');
		const { serverUrl, email } = await cuentaOTirar();

		const backoff = await leerBackoff();
		const ahoraMs = Date.now();

		const wasm = await cargarCrypto();
		const claveDisp = await obtenerClaveDeDispositivo(NOMBRE_CLAVE_DISP);
		const secretoBuf = await crypto.subtle.decrypt(
			{ name: 'AES-GCM', iv: base64ABytes(estado.secretoIvB64) as BufferSource },
			claveDisp,
			base64ABytes(estado.secretoCifradoB64) as BufferSource
		);
		const secreto = new Uint8Array(secretoBuf);
		const valido = wasm.totp_verificar(secreto, Number(codigo), BigInt(Math.floor(ahoraMs / 1000)));

		const { bloqueadoSegundos, nuevo } = siguienteBackoff(backoff, valido, ahoraMs);
		if (bloqueadoSegundos !== null) throw new Error(`Demasiados intentos — esperá ${bloqueadoSegundos}s.`);
		await guardarBackoff(nuevo);
		if (!valido) throw new Error('Código incorrecto.');

		const passphrase = wasm.totp_desenvolver_passphrase(
			secreto,
			base64ABytes(estado.nonceB64),
			base64ABytes(estado.cipherB64),
			aad(email)
		);
		return AuthService.login(serverUrl, email, passphrase);
	}
};
