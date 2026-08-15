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

function baseUrl(): string {
	return '';
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
	const s = get(sesion);
	const headers = new Headers(init.headers);
	headers.set('Content-Type', 'application/json');
	if (s.sessionId) headers.set('Authorization', `Bearer ${s.sessionId}`);

	const resp = await fetch(`${baseUrl()}${path}`, { ...init, headers });

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
