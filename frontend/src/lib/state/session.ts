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

// F-39: `clearOn` sólo `logout`, a propósito — el auto-bloqueo por
// inactividad no cierra la sesión HTTP ("sin cerrar la sesión HTTP (F-04)",
// spec F-39), sólo descarta el material criptográfico ya desbloqueado
// (`clavesDesbloqueadas`, abajo). Si `lock` también limpiara este store,
// el guard de `(app)/+layout.svelte` (que redirige a `/login` sin
// `sessionId`) expulsaría de la app entera en cada auto-bloqueo, exactamente
// lo que la spec dice que no debe pasar.
export const sesion = declararStore<SesionActual>(
	'sesion',
	{ sessionId: null, userId: null, email: null },
	{ ubicacion: 'memory', clearOn: ['logout'] }
);

/** Sólo poblado tras desbloquear con la passphrase — nunca persiste. */
export const clavesDesbloqueadas = declararStore<ClavesDesbloqueadas | null>('claves', null, {
	ubicacion: 'memory',
	clearOn: ['lock', 'logout']
});

/**
 * F-20/F-22: sólo UX (evitar mostrar un link a una pantalla que va a 403 —
 * el server-side es la única fuente de verdad real, `AdminUser` en cada
 * endpoint, BWN-08-001). `null` = todavía no se probó; se resuelve una sola
 * vez por sesión en `(app)/+layout.svelte` y lo reusa tanto el nav principal
 * como el guard de `(app)/admin/+layout.svelte`, en vez de que cada uno
 * dispare su propio `GET /admin/roles`.
 */
export const esAdmin = declararStore<boolean | null>('esAdmin', null, {
	ubicacion: 'memory',
	clearOn: ['logout']
});

/** `/me/preferences` (F-31/F-39) — nunca sensible, sobrevive lock/logout. */
export interface Preferencias {
	locale: 'en' | 'es';
	theme: 'light' | 'dark';
	clipboardClearMinutes: number;
	autoLockMinutes: number | null;
}

/**
 * F-31: `Accept-Language`/`navigator.language` sólo como default inicial —
 * `declararStore` únicamente lo usa si `localStorage` está vacío (primera
 * visita real en este navegador). Una vez que exista una preferencia real
 * (guardada localmente o traída de `/me/preferences` tras login), esto
 * nunca vuelve a pisarla.
 */
function localeInicial(): 'en' | 'es' {
	if (typeof navigator === 'undefined') return 'en';
	return navigator.language?.toLowerCase().startsWith('es') ? 'es' : 'en';
}

export const preferencias = declararStore<Preferencias>(
	'preferencias',
	{ locale: localeInicial(), theme: 'dark', clipboardClearMinutes: 1, autoLockMinutes: 15 },
	{ ubicacion: 'disk', clearOn: [] }
);
