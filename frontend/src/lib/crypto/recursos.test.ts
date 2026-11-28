// Autor: Athan Espinoza

// QA-14 (pendiente #103): tests unitarios de `recursos.ts`. El ida y vuelta
// de cifrado usa el WASM real de `ellkan-crypto` (cargado desde disco); la
// API y el sync se reemplazan por dobles que capturan lo que se enviaría.

import { beforeEach, describe, expect, it, vi } from 'vitest';
import { cargarCryptoEnNode } from '#lib/test/wasm-node';

const enviados = vi.hoisted(() => ({ posts: [] as { ruta: string; cuerpo: Record<string, string> }[] }));
const respuestasGet = vi.hoisted(() => new Map<string, unknown>());

vi.mock('./wasm', () => ({ cargarCrypto: cargarCryptoEnNode }));
vi.mock('#lib/api/client', () => {
	class ApiError extends Error {
		constructor(
			public status: number,
			public code: string,
			message: string
		) {
			super(message);
		}
	}
	return {
		ApiError,
		api: {
			get: vi.fn(async (ruta: string) => {
				if (!respuestasGet.has(ruta)) throw new ApiError(404, 'NOT_FOUND', ruta);
				return respuestasGet.get(ruta);
			}),
			post: vi.fn(async (ruta: string, cuerpo: Record<string, string>) => {
				enviados.posts.push({ ruta, cuerpo });
				return {};
			})
		}
	};
});
vi.mock('#lib/sync/notificador', () => ({
	notificarRecursoCreado: vi.fn(),
	notificarRecursoEditado: vi.fn(),
	notificarRecursoEliminado: vi.fn()
}));
vi.mock('#lib/sync/vinculacion', () => ({ obtenerVinculacion: vi.fn(), sesionRemotaVigente: vi.fn() }));
vi.mock('#lib/sync/remoteClient', () => ({ clienteRemoto: vi.fn() }));
vi.mock('#lib/sync/persistencia', () => ({ obtenerPersistencia: vi.fn(async () => 'full') }));
vi.mock('#lib/cache/metadataCache', () => ({ leerDeCache: vi.fn(), guardarEnCache: vi.fn() }));

const { comandoDeConexion, crearRecurso, infoConexion, urlSegura, verSecreto } = await import('./recursos');

async function clavesDePrueba() {
	const wasm = await cargarCryptoEnNode();
	const id = wasm.generar_identidad();
	return {
		x25519Private: id.x25519_private,
		ed25519Private: id.ed25519_private,
		x25519Public: id.x25519_public,
		ed25519Public: id.ed25519_public
	};
}

describe('comandoDeConexion', () => {
	it('arma el comando de cada protocolo y sólo muestra el puerto si no es el de siempre', () => {
		expect(comandoDeConexion({ resourceTypeSlug: 'ssh', usuario: 'ana', uri: 'srv.example.com' })).toBe('ssh ana@srv.example.com');
		expect(comandoDeConexion({ resourceTypeSlug: 'ssh', usuario: 'ana', uri: 'ssh://srv:2222' })).toBe('ssh ana@srv -p 2222');
		expect(comandoDeConexion({ resourceTypeSlug: 'postgresql', usuario: 'app', uri: 'db' })).toBe('psql -h db -p 5432 -U app');
		expect(comandoDeConexion({ resourceTypeSlug: 'rdp', usuario: '', uri: '10.0.0.5:3390' })).toBe('mstsc /v:10.0.0.5:3390');
		expect(comandoDeConexion({ resourceTypeSlug: 'login-password', usuario: 'ana', uri: 'example.com' })).toBeNull();
	});

	// Un recurso compartido o importado puede traer usuario/host armados para
	// que el comando copiado ejecute otra cosa al pegarlo en una terminal.
	it.each([
		['usuario con ;', 'x; rm -rf ~', 'srv'],
		['usuario con $()', '$(curl evil)', 'srv'],
		['usuario con espacio', 'ana -oProxyCommand=evil', 'srv'],
		['usuario que empieza con -', '-oProxyCommand=evil', 'srv'],
		['host que empieza con -', 'ana', '-oProxyCommand=evil'],
		['host con |', 'ana', 'srv|evil'],
		['host con comillas', 'ana', 'srv"evil']
	])('no ofrece comando con %s', (_caso, usuario, uri) => {
		expect(comandoDeConexion({ resourceTypeSlug: 'ssh', usuario, uri })).toBeNull();
	});

	it('infoConexion aplica el puerto por defecto', () => {
		expect(infoConexion({ resourceTypeSlug: 'mysql', uri: 'db' })).toEqual({ protocolo: 'MYSQL', puerto: 3306 });
	});
});

describe('urlSegura', () => {
	it('acepta http(s) y completa https:// cuando falta el esquema', () => {
		expect(urlSegura('https://example.com/login')).toBe('https://example.com/login');
		expect(urlSegura('example.com')).toBe('https://example.com');
		expect(urlSegura('localhost:8080/app')).toBe('https://localhost:8080/app');
	});

	it.each(['javascript:alert(1)', 'JavaScript://%0aalert(1)', 'data:text/html,<script>alert(1)</script>', 'vbscript:msgbox', ''])(
		'rechaza %s',
		(uri) => {
			expect(urlSegura(uri)).toBeNull();
		}
	);
});

describe('crearRecurso + verSecreto (cifrado real)', () => {
	beforeEach(() => {
		enviados.posts.length = 0;
		respuestasGet.clear();
		respuestasGet.set('/metadata-keys', []);
	});

	it('el secreto cifrado al crear se vuelve a abrir con la clave del dueño', async () => {
		const claves = await clavesDePrueba();
		const userId = crypto.randomUUID();
		await crearRecurso({ nombre: 'Correo', usuario: 'ana', password: 'contraseña-secreta', uri: 'mail.example.com', notas: '' }, claves, userId);

		const { ruta, cuerpo } = enviados.posts[0];
		expect(ruta).toBe('/resources');
		// Nada en claro viaja al servidor.
		expect(JSON.stringify(cuerpo)).not.toContain('contraseña-secreta');

		respuestasGet.set(`/resources/${cuerpo.id}/secret`, {
			sealed_dek_b64: cuerpo.sealed_dek_b64,
			secret_ciphertext_b64: cuerpo.secret_ciphertext_b64,
			secret_nonce_b64: cuerpo.secret_nonce_b64
		});
		const recurso = { id: cuerpo.id, createdBy: userId } as Parameters<typeof verSecreto>[0];
		const secreto = await verSecreto(recurso, claves);
		expect(secreto.password).toBe('contraseña-secreta');
	});

	it('el AAD ata el secreto al recurso y a su creador: con otro creador no abre', async () => {
		const claves = await clavesDePrueba();
		const userId = crypto.randomUUID();
		await crearRecurso({ nombre: 'Banco', usuario: 'ana', password: 'otra-clave', uri: 'banco.example', notas: '' }, claves, userId);
		const { cuerpo } = enviados.posts[0];
		respuestasGet.set(`/resources/${cuerpo.id}/secret`, {
			sealed_dek_b64: cuerpo.sealed_dek_b64,
			secret_ciphertext_b64: cuerpo.secret_ciphertext_b64,
			secret_nonce_b64: cuerpo.secret_nonce_b64
		});
		const recurso = { id: cuerpo.id, createdBy: crypto.randomUUID() } as Parameters<typeof verSecreto>[0];
		await expect(verSecreto(recurso, claves)).rejects.toBeDefined();
	});

	it('otra persona no puede abrir la DEK sellada para el dueño', async () => {
		const dueno = await clavesDePrueba();
		const otro = await clavesDePrueba();
		const userId = crypto.randomUUID();
		await crearRecurso({ nombre: 'Servidor', usuario: 'root', password: 'clave-root', uri: 'srv', notas: '' }, dueno, userId);
		const { cuerpo } = enviados.posts[0];
		respuestasGet.set(`/resources/${cuerpo.id}/secret`, {
			sealed_dek_b64: cuerpo.sealed_dek_b64,
			secret_ciphertext_b64: cuerpo.secret_ciphertext_b64,
			secret_nonce_b64: cuerpo.secret_nonce_b64
		});
		const recurso = { id: cuerpo.id, createdBy: userId } as Parameters<typeof verSecreto>[0];
		await expect(verSecreto(recurso, otro)).rejects.toBeDefined();
	});
});
