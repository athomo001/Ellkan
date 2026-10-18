// Autor: Athan Espinoza

// Modo escritorio: registra en `Ellkan.log` los CAMBIOS de estado de la app
// (pedido 2026-10-18: «que el log cuente qué está pasando, no los datos»):
// sesión iniciada o cerrada, bóveda bloqueada o desbloqueada, y el estado de
// la comunicación con el servidor (sube bien ↔ falla). Una línea por cambio,
// nunca una por cada pedido. Nunca secretos: sólo el correo de la sesión.

import { sesion, clavesDesbloqueadas } from '$lib/state/session';
import { estadoSync } from '$lib/sync/notificador';
import { registrar } from './registro';
import { enModoEscritorio } from './conectar';

let instalada = false;

export function vigilarEstados(): void {
	if (instalada || !enModoEscritorio()) return;
	instalada = true;

	let emailAnterior: string | null | undefined;
	sesion.subscribe((s) => {
		const email = s.email ?? null;
		if (emailAnterior !== undefined && email !== emailAnterior) {
			registrar('info', email ? `[sesión] iniciada (${email})` : '[sesión] cerrada');
		}
		emailAnterior = email;
	});

	let desbloqueadaAnterior: boolean | undefined;
	clavesDesbloqueadas.subscribe((c) => {
		const desbloqueada = !!c;
		if (desbloqueadaAnterior !== undefined && desbloqueada !== desbloqueadaAnterior) {
			registrar('info', desbloqueada ? '[bóveda] desbloqueada' : '[bóveda] bloqueada');
		}
		desbloqueadaAnterior = desbloqueada;
	});

	let errorAnterior: string | null | undefined;
	estadoSync.subscribe((e) => {
		if (errorAnterior !== undefined && e.ultimoError !== errorAnterior) {
			if (e.ultimoError && !errorAnterior) registrar('warn', '[servidor] la subida de cambios empezó a fallar:', e.ultimoError);
			else if (!e.ultimoError && errorAnterior) registrar('info', '[servidor] la subida de cambios volvió a funcionar');
		}
		errorAnterior = e.ultimoError;
	});
}
