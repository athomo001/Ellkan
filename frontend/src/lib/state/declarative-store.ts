// Autor: Athan Espinoza

// F-30/07-frontend-web.md §1: cada store se declara una sola vez, con su
// ubicación de storage y su política de limpieza — en vez de que cada
// componente lea/escriba sessionStorage/IndexedDB a mano en el punto donde
// lo necesita. Un registro único (`clearStoresOn`) es lo que permite que
// lock/logout limpien todo de forma completa y auditable.

import { writable, type Writable } from 'svelte/store';

export type Ubicacion = 'memory' | 'disk';
export type EventoLimpieza = 'lock' | 'logout';

interface DefinicionStore<T> {
	store: Writable<T>;
	ubicacion: Ubicacion;
	clearOn: EventoLimpieza[];
	clave: string;
	defaultValue: T;
}

const registro = new Map<string, DefinicionStore<unknown>>();

function leerDeDisco<T>(clave: string, defaultValue: T): T {
	if (typeof localStorage === 'undefined') return defaultValue;
	const crudo = localStorage.getItem(`ellkan:${clave}`);
	if (!crudo) return defaultValue;
	try {
		return JSON.parse(crudo) as T;
	} catch {
		return defaultValue;
	}
}

/**
 * Declara un store con su ubicación (`"memory"` → sólo en memoria, se
 * pierde al cerrar pestaña; `"disk"` → persiste en `localStorage`, no
 * usar nunca para material sensible) y su política de limpieza.
 *
 * **Passphrase y claves de sesión siempre van con `ubicacion: "memory"`**
 * (F-04, mismo criterio ya fijado para la extensión) — nunca `"disk"`.
 */
export function declararStore<T>(
	clave: string,
	defaultValue: T,
	opciones: { ubicacion: Ubicacion; clearOn: EventoLimpieza[] }
): Writable<T> {
	const inicial = opciones.ubicacion === 'disk' ? leerDeDisco(clave, defaultValue) : defaultValue;
	const store = writable<T>(inicial);

	if (opciones.ubicacion === 'disk' && typeof localStorage !== 'undefined') {
		store.subscribe((valor) => {
			localStorage.setItem(`ellkan:${clave}`, JSON.stringify(valor));
		});
	}

	registro.set(clave, { store, ubicacion: opciones.ubicacion, clearOn: opciones.clearOn, clave, defaultValue });
	return store;
}

/**
 * Limpia todos los stores registrados que incluyan `evento` en su
 * `clearOn` — llamado desde `lock()`/`logout()`, nunca disperso por
 * feature (evita que una feature nueva "se olvide" de limpiar lo suyo).
 */
export function limpiarStoresEn(evento: EventoLimpieza): void {
	for (const def of registro.values()) {
		if (def.clearOn.includes(evento)) {
			def.store.set(def.defaultValue);
			if (def.ubicacion === 'disk' && typeof localStorage !== 'undefined') {
				localStorage.removeItem(`ellkan:${def.clave}`);
			}
		}
	}
}
