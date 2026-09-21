// Autor: Athan Espinoza

// F-47 (modo conectado): cliente HTTP mínimo para hablar con un servidor
// Ellkan REMOTO — deliberadamente separado de `$lib/api/client.ts`. Ese
// cliente está atado al store global de sesión LOCAL y a `baseUrl()` (el
// backend local), con efectos secundarios reales en un 401 (logout +
// redirect a `/login`) que serían un bug acá: una sesión remota vencida o
// un servidor remoto caído nunca deben desloguear al usuario de su propia
// bóveda local, sólo fallar el sync puntual.

export class RemoteApiError extends Error {
	constructor(
		public status: number,
		public code: string,
		message: string
	) {
		super(message);
	}
}

async function pedido<T>(serverUrl: string, sessionId: string | null, path: string, init: RequestInit = {}): Promise<T> {
	const headers = new Headers(init.headers);
	headers.set('Content-Type', 'application/json');
	if (sessionId) headers.set('Authorization', `Bearer ${sessionId}`);

	const resp = await fetch(`${serverUrl}${path}`, { ...init, headers });
	if (resp.status === 204) return undefined as T;

	const texto = await resp.text();
	const cuerpo = texto ? JSON.parse(texto) : undefined;
	if (!resp.ok) {
		const err = cuerpo?.error ?? { code: 'UNKNOWN', message: resp.statusText };
		throw new RemoteApiError(resp.status, err.code, err.message);
	}
	return cuerpo as T;
}

export interface ClienteRemoto {
	get<T>(path: string): Promise<T>;
	post<T>(path: string, body?: unknown): Promise<T>;
	put<T>(path: string, body?: unknown, headers?: HeadersInit): Promise<T>;
	delete<T>(path: string): Promise<T>;
}

export function clienteRemoto(serverUrl: string, sessionId: string | null): ClienteRemoto {
	return {
		get: <T>(path: string) => pedido<T>(serverUrl, sessionId, path, { method: 'GET' }),
		post: <T>(path: string, body?: unknown) =>
			pedido<T>(serverUrl, sessionId, path, { method: 'POST', body: body !== undefined ? JSON.stringify(body) : undefined }),
		put: <T>(path: string, body?: unknown, headers?: HeadersInit) =>
			pedido<T>(serverUrl, sessionId, path, { method: 'PUT', body: body !== undefined ? JSON.stringify(body) : undefined, headers }),
		delete: <T>(path: string) => pedido<T>(serverUrl, sessionId, path, { method: 'DELETE' })
	};
}
