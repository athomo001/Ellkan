// Autor: Athan Espinoza

// Cliente HTTP base — agrega el `Authorization: Bearer <session_id>` desde
// el store de sesión, y expone el envelope de error único del backend
// (08-backend.md) como una excepción tipada en vez de que cada caller
// tenga que repetir el parseo.

import { get } from 'svelte/store';
import { goto } from '$app/navigation';
import { sesion } from '$lib/state/session';
import { limpiarStoresEn } from '$lib/state/declarative-store';

export class ApiError extends Error {
	constructor(
		public status: number,
		public code: string,
		message: string
	) {
		super(message);
	}
}

// Modo escritorio (Tauri): el backend corre in-process en loopback, no en el
// mismo origen que la SPA. `'__TAURI_INTERNALS__' in window` es el marcador
// que Tauri 2 inyecta siempre en su webview — nunca está presente en un
// navegador normal, así que en modo servidor esto sigue devolviendo '' como
// siempre.
//
// El puerto ya no es fijo (spec/13 §3, backend desde 2026-09-16): el lado
// Rust bindea uno real (reusa el persistido, o autoelige uno libre del
// rango IANA privado en el primer arranque) ANTES de que la ventana quede
// visible (`preparar_backend_local` corre bloqueante dentro de
// `tauri::App::setup`, `src-tauri/src/lib.rs`) — así que para cuando este
// código corre, el comando `puerto_backend` ya tiene un valor real, sin
// ninguna carrera que resolver acá. Se resuelve una sola vez por sesión de
// la app y se cachea (el puerto no cambia mientras el proceso sigue vivo).
let puertoCacheado: number | null = null;

export async function baseUrl(): Promise<string> {
	if (typeof window === 'undefined' || !('__TAURI_INTERNALS__' in window)) return '';
	if (puertoCacheado === null) {
		const { invoke } = await import('@tauri-apps/api/core');
		puertoCacheado = await invoke<number>('puerto_backend');
	}
	return `http://127.0.0.1:${puertoCacheado}`;
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
	const s = get(sesion);
	const headers = new Headers(init.headers);
	headers.set('Content-Type', 'application/json');
	if (s.sessionId) headers.set('Authorization', `Bearer ${s.sessionId}`);

	const resp = await fetch(`${await baseUrl()}${path}`, { ...init, headers });

	if (resp.status === 204) return undefined as T;

	const texto = await resp.text();
	const cuerpo = texto ? JSON.parse(texto) : undefined;

	if (!resp.ok) {
		const err = cuerpo?.error ?? { code: 'UNKNOWN', message: resp.statusText };

		// Hallazgo real de uso: la sesión vencía server-side (TTL) y cada
		// página mostraba su propio error genérico ("no se pudo cargar el
		// vault") en vez de mandar a login — sólo dispara si *mandamos* un
		// `Authorization` (creíamos tener sesión) y igual volvió `401`: eso
		// es "la sesión ya no es válida", distinto de un intento de login
		// con contraseña incorrecta (ahí nunca hay `Authorization` todavía,
		// y sí queremos que la página de login muestre el error en vez de
		// redirigir a sí misma).
		if (resp.status === 401 && s.sessionId) {
			limpiarStoresEn('logout');
			goto('/login');
		}

		throw new ApiError(resp.status, err.code, err.message);
	}

	return cuerpo as T;
}

export const api = {
	get: <T>(path: string) => request<T>(path, { method: 'GET' }),
	post: <T>(path: string, body?: unknown) =>
		request<T>(path, { method: 'POST', body: body !== undefined ? JSON.stringify(body) : undefined }),
	put: <T>(path: string, body?: unknown, headers?: HeadersInit) =>
		request<T>(path, { method: 'PUT', body: body !== undefined ? JSON.stringify(body) : undefined, headers }),
	patch: <T>(path: string, body?: unknown) =>
		request<T>(path, { method: 'PATCH', body: body !== undefined ? JSON.stringify(body) : undefined }),
	delete: <T>(path: string) => request<T>(path, { method: 'DELETE' })
};
