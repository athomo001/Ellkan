// Autor: Athan Espinoza

// F-30/07-frontend-web.md §1: cada store se declara una sola vez, con su
// ubicación de storage y su política de limpieza — en vez de que cada
// componente lea/escriba sessionStorage/IndexedDB a mano en el punto donde
// lo necesita. Un registro único (`clearStoresOn`) es lo que permite que
// lock/logout limpien todo de forma completa y auditable.

import { writable, type Writable } from 'svelte/store';

export type Ubicacion = 'memory' | 'session' | 'disk';
export type EventoLimpieza = 'lock' | 'logout';

interface DefinicionStore<T> {
	store: Writable<T>;
	ubicacion: Ubicacion;
	clearOn: EventoLimpieza[];
	clave: string;
	defaultValue: T;
}

const registro = new Map<string, DefinicionStore<unknown>>();

function storageDe(ubicacion: Ubicacion): Storage | undefined {
	if (ubicacion === 'disk') return typeof localStorage === 'undefined' ? undefined : localStorage;
	if (ubicacion === 'session') return typeof sessionStorage === 'undefined' ? undefined : sessionStorage;
	return undefined;
}

function leerDeStorage<T>(ubicacion: Ubicacion, clave: string, defaultValue: T): T {
	const storage = storageDe(ubicacion);
	if (!storage) return defaultValue;
	const crudo = storage.getItem(`ellkan:${clave}`);
	if (!crudo) return defaultValue;
	try {
		return JSON.parse(crudo) as T;
	} catch {
		return defaultValue;
	}
}

/**
 * Declara un store con su ubicación y su política de limpieza:
 * - `"memory"` → sólo en memoria, se pierde con cualquier reload (F5
 *   incluido) — para material sensible de verdad (clave privada
 *   desenvuelta, `clavesDesbloqueadas`), nunca baja de acá.
 * - `"session"` → `sessionStorage`, sobrevive un reload de la misma
 *   pestaña pero se pierde al cerrarla — para lo que no es sensible en sí
 *   (ej. el id de sesión HTTP, un bearer token) pero tampoco debería
 *   sobrevivir más allá de la pestaña actual. Antes no existía este nivel
 *   intermedio, así que todo lo que necesitaba sobrevivir un F5 terminaba
 *   forzado a `"memory"` (perdido igual) — bug real, no una decisión.
 * - `"disk"` → persiste en `localStorage`, nunca usar para nada sensible.
 *
 * **Passphrase y claves ya desenvueltas siempre van con `ubicacion:
 * "memory"`** (F-04) — nunca `"session"` ni `"disk"`.
 */
export function declararStore<T>(
	clave: string,
	defaultValue: T,
	opciones: { ubicacion: Ubicacion; clearOn: EventoLimpieza[] }
): Writable<T> {
	const inicial = leerDeStorage(opciones.ubicacion, clave, defaultValue);
	const store = writable<T>(inicial);

	const storage = storageDe(opciones.ubicacion);
	if (storage) {
		store.subscribe((valor) => {
			storage.setItem(`ellkan:${clave}`, JSON.stringify(valor));
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
			const storage = storageDe(def.ubicacion);
			storage?.removeItem(`ellkan:${def.clave}`);
		}
	}
}
