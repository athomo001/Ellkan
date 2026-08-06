// Autor: Athan Espinoza

// Estado de sesión — declarado vía `declararStore` (07-frontend-web.md §1).
// La clave privada y la sesión HTTP viven en memoria (`"memory"`, F-04):
// se pierden al cerrar la pestaña, y se limpian explícitamente en
// lock/logout — nunca tocan disco.

import { declararStore } from './declarative-store';

export interface ClavesDesbloqueadas {
	x25519Private: Uint8Array;
	ed25519Private: Uint8Array;
	x25519Public: Uint8Array;
	ed25519Public: Uint8Array;
}

export interface SesionActual {
	sessionId: string | null;
	userId: string | null;
	email: string | null;
}

export const sesion = declararStore<SesionActual>(
	'sesion',
	{ sessionId: null, userId: null, email: null },
	{ ubicacion: 'memory', clearOn: ['lock', 'logout'] }
);

/** Sólo poblado tras desbloquear con la passphrase — nunca persiste. */
export const clavesDesbloqueadas = declararStore<ClavesDesbloqueadas | null>('claves', null, {
	ubicacion: 'memory',
	clearOn: ['lock', 'logout']
});

/** `/me/preferences` (F-31/F-39) — nunca sensible, sobrevive lock/logout. */
export interface Preferencias {
	locale: 'en' | 'es';
	theme: 'light' | 'dark';
	clipboardClearMinutes: number;
	autoLockMinutes: number | null;
}

export const preferencias = declararStore<Preferencias>(
	'preferencias',
	{ locale: 'es', theme: 'dark', clipboardClearMinutes: 1, autoLockMinutes: 15 },
	{ ubicacion: 'disk', clearOn: [] }
);
