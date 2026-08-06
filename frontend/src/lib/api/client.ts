// Autor: Athan Espinoza

// Cliente HTTP base — agrega el `Authorization: Bearer <session_id>` desde
// el store de sesión, y expone el envelope de error único del backend
// (08-backend.md) como una excepción tipada en vez de que cada caller
// tenga que repetir el parseo.

import { get } from 'svelte/store';
import { sesion } from '$lib/state/session';

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
		throw new ApiError(resp.status, err.code, err.message);
	}

	return cuerpo as T;
}

export const api = {
	get: <T>(path: string) => request<T>(path, { method: 'GET' }),
	post: <T>(path: string, body?: unknown) =>
		request<T>(path, { method: 'POST', body: body !== undefined ? JSON.stringify(body) : undefined }),
	put: <T>(path: string, body?: unknown) =>
		request<T>(path, { method: 'PUT', body: body !== undefined ? JSON.stringify(body) : undefined }),
	patch: <T>(path: string, body?: unknown) =>
		request<T>(path, { method: 'PATCH', body: body !== undefined ? JSON.stringify(body) : undefined }),
	delete: <T>(path: string) => request<T>(path, { method: 'DELETE' })
};
