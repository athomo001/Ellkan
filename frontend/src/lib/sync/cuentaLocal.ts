// Autor: Athan Espinoza

// Punto 6 de la lista de pendientes de escritorio: la cuenta local única nace
// desconectada y con el correo que el usuario haya tipeado; para vincularla
// después a una cuenta del servidor central ese correo tiene que coincidir
// con el de allá — de ahí que haga falta poder cambiarlo.
//
// El cambio en sí (re-sellar el blob de la clave privada, que usa el correo
// como AAD, + `PUT /me/email`) vive en `$lib/crypto/identity.ts`. Este módulo
// orquesta lo que rodea al cambio del lado del cliente: lo que estaba
// guardado POR correo y se rompería o quedaría huérfano.

import { get } from 'svelte/store';
import { cambiarEmailDeCuenta } from '$lib/crypto/identity';
import * as llaveroLocal from '$lib/crypto/llavero-local';
import * as totpLocal from '$lib/crypto/totp-local';
import { moverTokenSeguridad } from '$lib/state/securityToken';
import { sesion } from '$lib/state/session';
import { obtenerVinculacion } from './vinculacion';

export interface ResultadoCambioEmail {
	email: string;
	/** `true` si había desbloqueo rápido (llavero del SO o código local) y
	 * hubo que desactivarlo: ambos envuelven la passphrase con el correo como
	 * contexto criptográfico, así que dejan de servir con el correo nuevo y
	 * el usuario tiene que volver a activarlos. */
	desbloqueoRapidoDesactivado: boolean;
}

/** El correo no se puede cambiar mientras la bóveda esté conectada a un
 * servidor: la vinculación (`vinculacion.ts`) y su cursor de sync están
 * guardados por correo, y la identidad que el servidor conoce es la del
 * correo con el que se vinculó. */
export class CambioEmailBloqueado extends Error {
	constructor() {
		super('Desconectá la bóveda del servidor antes de cambiar el correo.');
	}
}

/** Precondiciones del cambio que el usuario puede corregir — la UI las
 * traduce por `codigo`. Todo lo demás que falla es del backend (`ApiError`,
 * p. ej. correo inválido o en uso) o abrir el blob (contraseña incorrecta). */
export class CambioEmailNoAplica extends Error {
	constructor(public codigo: 'sin_sesion' | 'mismo_correo') {
		super(codigo === 'sin_sesion' ? 'No hay una sesión activa.' : 'Ese ya es el correo de esta cuenta.');
	}
}

export async function cambiarEmailLocal(emailNuevo: string, passphrase: string): Promise<ResultadoCambioEmail> {
	const emailActual = get(sesion).email;
	if (!emailActual) throw new CambioEmailNoAplica('sin_sesion');
	if (obtenerVinculacion(emailActual)) throw new CambioEmailBloqueado();

	const nuevo = emailNuevo.trim();
	if (nuevo === emailActual) throw new CambioEmailNoAplica('mismo_correo');

	// Si esto falla (passphrase incorrecta, correo inválido o en uso) no se
	// tocó nada: el blob se abre primero y el backend aplica todo o nada.
	const guardado = await cambiarEmailDeCuenta(emailActual, nuevo, passphrase);

	moverTokenSeguridad(emailActual, guardado);

	// Con el correo ya cambiado en el backend, lo que sigue es limpieza
	// local — un fallo acá (p. ej. el llavero del SO no responde) nunca debe
	// presentarse como si el cambio de correo hubiera fallado.
	let desbloqueoRapidoDesactivado = false;
	try {
		if (llaveroLocal.estaActivo(emailActual)) {
			await llaveroLocal.desactivar(emailActual);
			desbloqueoRapidoDesactivado = true;
		}
	} catch {
		desbloqueoRapidoDesactivado = true;
	}
	try {
		if (totpLocal.estaActivo(emailActual)) {
			await totpLocal.desactivar(emailActual);
			desbloqueoRapidoDesactivado = true;
		}
	} catch {
		desbloqueoRapidoDesactivado = true;
	}

	sesion.update((s) => ({ ...s, email: guardado }));
	return { email: guardado, desbloqueoRapidoDesactivado };
}
