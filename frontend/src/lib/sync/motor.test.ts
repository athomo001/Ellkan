// Autor: Athan Espinoza

// Pendiente #103: tests unitarios del motor de sync (`motor.ts`). La API
// local, el servidor remoto y la cola de pendientes son dobles en memoria;
// se prueba qué decide el motor con cada caso del delta de `/sync`.

import { beforeEach, describe, expect, it, vi } from 'vitest';

type Llamada = { metodo: string; ruta: string; cuerpo?: unknown; cabeceras?: unknown };

const h = vi.hoisted(() => {
	class ApiError extends Error {
		constructor(
			public status: number,
			public code: string,
			message: string
		) {
			super(message);
		}
	}
	class RemoteApiError extends ApiError {}
	return {
		ApiError,
		RemoteApiError,
		local: [] as Llamada[],
		recursosLocales: new Map<string, { updated_at: string; metadata_ciphertext_b64: string }>(),
		carpetasLocales: [] as { folder_id: string }[],
		postFalla: null as null | Error,
		deltas: [] as unknown[],
		pendientes: {} as Record<string, string>,
		cursor: null as string | null,
		sesionesOlvidadas: 0
	};
});

vi.mock('$lib/api/client', () => ({
	ApiError: h.ApiError,
	api: {
		get: vi.fn(async (ruta: string) => {
			h.local.push({ metodo: 'GET', ruta });
			if (ruta === '/folders') return h.carpetasLocales;
			if (ruta === '/tags') return [];
			const id = ruta.match(/^\/resources\/([^/]+)$/)?.[1];
			if (id && h.recursosLocales.has(id)) return h.recursosLocales.get(id);
			throw new h.ApiError(404, 'NOT_FOUND', ruta);
		}),
		getTodo: vi.fn(async () => []),
		post: vi.fn(async (ruta: string, cuerpo: unknown) => {
			h.local.push({ metodo: 'POST', ruta, cuerpo });
			if (h.postFalla) throw h.postFalla;
			return {};
		}),
		put: vi.fn(async (ruta: string, cuerpo: unknown, cabeceras: unknown) => {
			h.local.push({ metodo: 'PUT', ruta, cuerpo, cabeceras });
			return {};
		}),
		delete: vi.fn(async (ruta: string) => {
			h.local.push({ metodo: 'DELETE', ruta });
			return undefined;
		})
	}
}));

vi.mock('$lib/state/session', async () => {
	const { writable } = await import('svelte/store');
	return {
		sesion: writable({ email: 'ana@x.com', userId: 'u-local' }),
		clavesDesbloqueadas: writable({ privada: 'x' })
	};
});

vi.mock('./remoteClient', () => ({
	RemoteApiError: h.RemoteApiError,
	clienteRemoto: vi.fn(() => ({
		get: vi.fn(async (ruta: string) => {
			expect(ruta.startsWith('/sync')).toBe(true);
			const siguiente = h.deltas.shift();
			if (siguiente instanceof Error) throw siguiente;
			return siguiente;
		}),
		getTodo: vi.fn(async () => [])
	}))
}));

vi.mock('./vinculacion', () => ({
	obtenerVinculacion: vi.fn(() => ({ serverUrl: 'https://servidor' })),
	obtenerCursor: vi.fn(() => h.cursor),
	guardarCursor: vi.fn((_email: string, cursor: string) => {
		h.cursor = cursor;
	}),
	sesionRemotaVigente: vi.fn(async () => 'sesion-remota'),
	olvidarSesionRemota: vi.fn(() => {
		h.sesionesOlvidadas++;
	}),
	fijarIdentidadDelServidor: vi.fn(async () => {})
}));

vi.mock('./pendientes', () => ({
	obtenerPendientes: vi.fn(() => ({ ...h.pendientes })),
	marcarPendiente: vi.fn((_e: string, id: string, op: string) => {
		h.pendientes[id] = op;
	}),
	quitarPendiente: vi.fn((_e: string, id: string) => {
		delete h.pendientes[id];
	})
}));

vi.mock('./persistencia', () => ({ obtenerPersistencia: vi.fn(async () => 'full') }));
vi.mock('./adaptacion', () => ({
	necesitaAdaptacion: vi.fn(() => false),
	adaptarRecurso: vi.fn(),
	marcarAdaptado: vi.fn(),
	esAdaptado: vi.fn(() => false)
}));
vi.mock('./avatar', () => ({ sincronizarAvatar: vi.fn(async () => false) }));
vi.mock('./kit', () => ({ sincronizarKit: vi.fn(async () => {}) }));
vi.mock('./notificador', () => ({ subirPendientes: vi.fn(async () => 0) }));
vi.mock('$lib/tauri/registro', () => ({ registrar: vi.fn() }));
vi.mock('$lib/crypto/recursos', () => ({ olvidarSecretoEnMemoria: vi.fn() }));
vi.mock('../crypto/wasm', () => ({ cargarCrypto: vi.fn() }));

import { sincronizarAhora } from './motor';

function recurso(id: string, extra: Record<string, unknown> = {}) {
	return {
		id,
		deleted: false,
		resource_type_slug: 'login-password',
		metadata_ciphertext_b64: `meta-${id}`,
		metadata_nonce_b64: 'nonce',
		created_by: 'u-local',
		metadata_key_type: 'user_key',
		metadata_key_id: null,
		folder_id: null,
		secret: { sealed_dek_b64: 'dek', secret_ciphertext_b64: 'sec', secret_nonce_b64: 'n2' },
		...extra
	};
}

function delta(resources: unknown[], extra: Record<string, unknown> = {}) {
	return { cursor: 'cursor-nuevo', resources, folders: [], tags: [], ...extra };
}

const escrituras = () => h.local.filter((l) => l.metodo !== 'GET');

beforeEach(() => {
	h.local.length = 0;
	h.recursosLocales.clear();
	h.carpetasLocales.length = 0;
	h.postFalla = null;
	h.deltas.length = 0;
	h.pendientes = {};
	h.cursor = null;
	h.sesionesOlvidadas = 0;
});

describe('sincronizarAhora', () => {
	it('crea localmente lo nuevo del servidor y guarda el cursor', async () => {
		h.deltas.push(delta([recurso('r1', { folder_id: 'f1' })]));
		const r = await sincronizarAhora();
		expect(r.recursosNuevosOActualizados).toBe(1);
		expect(escrituras()).toEqual([
			{
				metodo: 'POST',
				ruta: '/resources',
				cuerpo: expect.objectContaining({ id: 'r1', metadata_ciphertext_b64: 'meta-r1', secret_ciphertext_b64: 'sec' })
			},
			{ metodo: 'PUT', ruta: '/resources/r1/move', cuerpo: { folder_id: 'f1' }, cabeceras: undefined }
		]);
		expect(h.cursor).toBe('cursor-nuevo');
	});

	it('el eco de un cambio propio no se reaplica y sale de la cola', async () => {
		h.recursosLocales.set('r1', { updated_at: '2026-01-01T00:00:00Z', metadata_ciphertext_b64: 'meta-r1' });
		h.pendientes = { r1: 'subir' };
		h.deltas.push(delta([recurso('r1')]));
		const r = await sincronizarAhora();
		expect(escrituras()).toEqual([]);
		expect(h.pendientes).toEqual({});
		expect(r.recursosEnConflicto).toBe(0);
	});

	it('una edición del servidor reemplaza la local con If-Match y el usuario local como destinatario', async () => {
		h.recursosLocales.set('r1', { updated_at: '2026-01-01T00:00:00Z', metadata_ciphertext_b64: 'viejo' });
		h.deltas.push(delta([recurso('r1')]));
		const r = await sincronizarAhora();
		expect(r.recursosNuevosOActualizados).toBe(1);
		const put = escrituras()[0];
		expect(put.ruta).toBe('/resources/r1');
		expect(put.cabeceras).toEqual({ 'If-Match': '2026-01-01T00:00:00Z' });
		expect((put.cuerpo as { envelopes: { recipient_user_id: string }[] }).envelopes[0].recipient_user_id).toBe('u-local');
	});

	it('gana un borrado local pendiente: no se vuelve a crear', async () => {
		h.pendientes = { r1: 'borrar' };
		h.deltas.push(delta([recurso('r1')]));
		await sincronizarAhora();
		expect(escrituras()).toEqual([]);
		expect(h.pendientes).toEqual({ r1: 'borrar' });
	});

	it('un 409 al crear (borrado acá sin avisar) lo pone en la cola para borrar', async () => {
		h.postFalla = new h.ApiError(409, 'CONFLICT', 'ya existe borrado');
		h.deltas.push(delta([recurso('r1')]));
		const r = await sincronizarAhora();
		expect(r.recursosNuevosOActualizados).toBe(0);
		expect(h.pendientes).toEqual({ r1: 'borrar' });
	});

	it('un borrado del servidor borra la copia local', async () => {
		h.deltas.push(delta([{ ...recurso('r1'), deleted: true }]));
		const r = await sincronizarAhora();
		expect(r.recursosBorrados).toBe(1);
		expect(escrituras()).toEqual([{ metodo: 'DELETE', ruta: '/resources/r1' }]);
	});

	it('con la sesión remota vencida pide otra y reintenta una vez', async () => {
		h.deltas.push(new h.RemoteApiError(401, 'UNAUTHORIZED', 'vencida'), delta([]));
		await sincronizarAhora();
		expect(h.sesionesOlvidadas).toBe(1);
		expect(h.cursor).toBe('cursor-nuevo');
	});

	it('carpetas: crea las que faltan, no toca las que existen y borra las borradas', async () => {
		h.carpetasLocales.push({ folder_id: 'existe' });
		const carpeta = (folder_id: string, deleted = false) => ({
			folder_id,
			deleted,
			parent_folder_id: null,
			name_ciphertext_b64: 'n',
			name_nonce_b64: 'nn'
		});
		h.deltas.push(delta([], { folders: [carpeta('nueva'), carpeta('existe'), carpeta('vieja', true)] }));
		const r = await sincronizarAhora();
		expect(r.carpetasNuevas).toBe(1);
		expect(r.carpetasBorradas).toBe(1);
		expect(escrituras().map((l) => `${l.metodo} ${l.ruta}`)).toEqual(['POST /folders', 'DELETE /folders/vieja']);
	});
});
