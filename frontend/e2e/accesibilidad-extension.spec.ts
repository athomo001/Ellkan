// Autor: Athan Espinoza

// Pendiente #66 (WCAG 2.2 AA en lo que faltaba): axe sobre la extensión —
// las vistas del popup y la UI que el content script inyecta en las páginas
// (menú inline de autofill y barra "¿guardar esta contraseña?").
//
// Sin navegador con la extensión cargada: se sirve el build (`extension/dist`,
// `node build.mjs`) desde un origen de prueba y se le da un `chrome` simulado
// cuyo puerto responde al protocolo del service worker (`PortClient`:
// handshake → `ellkan.port.ready`, cada pedido → `[requestId, 'SUCCESS',
// datos]`) con respuestas fijas por `tipo`. La UI inyectada vive en shadow
// roots cerrados; en el test se abren (`attachShadow` parcheado) para que axe
// pueda entrar — el aislamiento real no cambia nada de lo que se audita.

import { test, expect, type Page } from '@playwright/test';
import { existsSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { auditar } from './axe';

const DIST = fileURLToPath(new URL('../../extension/dist/', import.meta.url));
// https: contexto seguro, como `chrome-extension://` (`crypto.randomUUID`).
const ORIGEN_EXTENSION = 'https://extension.test';
const PAGINA_LOGIN = 'https://login.ejemplo.test/';

const TIPOS_MIME: Record<string, string> = {
	html: 'text/html',
	js: 'text/javascript',
	css: 'text/css',
	json: 'application/json',
	wasm: 'application/wasm',
	svg: 'image/svg+xml',
	png: 'image/png',
	woff2: 'font/woff2'
};

const SESION = { sessionId: 's-1', email: 'ana.perez@ellkan.test', serverUrl: 'https://ellkan.test' };
const ITEMS = [
	{
		id: 'r-1',
		nombre: 'Correo corporativo',
		usuario: 'ana.perez',
		uri: 'https://correo.ellkan.test',
		matching: 'host',
		resourceTypeSlug: 'login-password',
		createdBy: 'u-1',
		metadataKeyType: 'user_key',
		metadataKeyId: null,
		updatedAt: '2026-11-20T10:00:00Z',
		createdAt: '2026-11-01T10:00:00Z'
	},
	{
		id: 'r-2',
		nombre: 'Servidor de base de datos',
		usuario: 'postgres',
		uri: 'db.ellkan.test:5432',
		matching: 'host',
		resourceTypeSlug: 'postgresql',
		createdBy: 'u-1',
		metadataKeyType: 'user_key',
		metadataKeyId: null,
		updatedAt: '2026-11-10T10:00:00Z',
		createdAt: '2026-10-01T10:00:00Z'
	}
];

/** `chrome` simulado: el puerto contesta por `tipo` con `respuestas` (lo que
 * no está, `null`). Va como init script, antes que cualquier script de la
 * página; también abre los shadow roots para axe. */
async function simularChrome(page: Page, respuestas: Record<string, unknown>): Promise<void> {
	await page.addInitScript(
		({ respuestas, origen }) => {
			const original = Element.prototype.attachShadow;
			Element.prototype.attachShadow = function (init: ShadowRootInit) {
				return original.call(this, { ...init, mode: 'open' });
			};
			const evento = () => {
				const oyentes: ((...a: unknown[]) => void)[] = [];
				return { addListener: (f: (...a: unknown[]) => void) => oyentes.push(f), removeListener: () => {}, oyentes };
			};
			const almacen = () => {
				const datos: Record<string, unknown> = {};
				return {
					get: async () => ({ ...datos }),
					set: async (items: Record<string, unknown>) => void Object.assign(datos, items),
					remove: async () => {}
				};
			};
			(window as unknown as { chrome: unknown }).chrome = {
				runtime: {
					id: 'ellkan-test',
					getURL: (ruta: string) => `${origen}/${ruta.replace(/^\//, '')}`,
					onMessage: evento(),
					sendMessage: async () => null,
					connect: () => {
						const alMensaje = evento();
						const responder = (m: unknown) => setTimeout(() => alMensaje.oyentes.forEach((f) => f(m)), 0);
						return {
							name: 'test',
							onMessage: alMensaje,
							onDisconnect: evento(),
							disconnect: () => {},
							postMessage: (pedido: { requestId: string; tipo: string }) => {
								if (pedido.tipo === 'HANDSHAKE') return responder(['ellkan.port.ready']);
								responder([pedido.requestId, 'SUCCESS', respuestas[pedido.tipo] ?? null]);
							}
						};
					}
				},
				storage: { local: almacen(), session: almacen() },
				tabs: { query: async () => [{ id: 1, url: 'https://correo.ellkan.test/login' }], create: async () => ({}) }
			};
		},
		{ respuestas, origen: ORIGEN_EXTENSION }
	);
}

/** Sirve `extension/dist` en `ORIGEN_EXTENSION`; el resto de la red, 404. */
async function servirExtension(page: Page): Promise<void> {
	await page.route('**/*', (route) => {
		const url = new URL(route.request().url());
		if (url.origin === ORIGEN_EXTENSION) {
			const archivo = DIST + decodeURIComponent(url.pathname).replace(/^\//, '');
			if (!existsSync(archivo)) return route.fulfill({ status: 404 });
			const ext = archivo.split('.').pop() ?? '';
			return route.fulfill({ body: readFileSync(archivo), contentType: TIPOS_MIME[ext] ?? 'application/octet-stream' });
		}
		if (url.href === PAGINA_LOGIN) {
			return route.fulfill({
				contentType: 'text/html',
				body: `<!doctype html><html lang="es"><head><title>Ingresar — Ejemplo</title></head><body><main>
					<h1>Ingresar</h1>
					<form onsubmit="event.preventDefault()">
						<label>Usuario <input name="username" autocomplete="username"></label>
						<label>Contraseña <input type="password" name="password" autocomplete="current-password"></label>
						<button type="submit">Entrar</button>
					</form></main></body></html>`
			});
		}
		return route.fulfill({ status: 404 });
	});
}

async function abrirPopup(page: Page, respuestas: Record<string, unknown>): Promise<void> {
	await page.setViewportSize({ width: 800, height: 600 });
	await simularChrome(page, respuestas);
	await servirExtension(page);
	await page.goto(`${ORIGEN_EXTENSION}/popup/index.html`);
	await expect(page.locator('#vista-cargando')).toBeHidden();
}

const errores: string[] = [];

test.describe('extensión', () => {
	// En CI el build va antes (ci.yml), así que ahí faltar es un error, no un salto.
	test.skip(!process.env.CI && !existsSync(`${DIST}popup/index.html`), 'falta el build de la extensión (node build.mjs en extension/)');

	test.beforeEach(({ page }) => {
		errores.length = 0;
		page.on('pageerror', (e) => errores.push(e.message));
	});
	test.afterEach(() => {
		expect(errores, 'el popup no debería romperse con el service worker simulado').toEqual([]);
	});

	test('popup: login', async ({ page }) => {
		await abrirPopup(page, { APP_ESCRITORIO_DISPONIBLE: false });
		await expect(page.locator('#vista-login')).toBeVisible();
		expect(await auditar(page)).toEqual([]);
	});

	test('popup: desbloqueo de una cuenta guardada', async ({ page }) => {
		await abrirPopup(page, { AUTH_ESTADO_CUENTA: { serverUrl: SESION.serverUrl, email: SESION.email, lockedPorInactividad: true } });
		await expect(page.locator('#vista-desbloqueo')).toBeVisible();
		expect(await auditar(page)).toEqual([]);
	});

	test('popup: verificación de dispositivo', async ({ page }) => {
		await abrirPopup(page, {
			AUTH_ESTADO_PENDIENTE_DISPOSITIVO: { serverUrl: SESION.serverUrl, email: SESION.email, deviceChallengeId: 'd-1' }
		});
		await expect(page.locator('#vista-dispositivo')).toBeVisible();
		expect(await auditar(page)).toEqual([]);
	});

	test('popup: segundo factor', async ({ page }) => {
		await abrirPopup(page, {
			APP_ESCRITORIO_DISPONIBLE: false,
			AUTH_LOGIN: { estado: 'pendiente_mfa', sessionId: 's-1' }
		});
		await page.locator('#vista-login input[type="email"]').fill(SESION.email);
		await page.locator('#vista-login input[type="password"]').fill('una frase de prueba bastante larga');
		await page.locator('#boton-login').click();
		await expect(page.locator('#vista-mfa')).toBeVisible();
		expect(await auditar(page)).toEqual([]);
	});

	test('popup: bóveda, detalle, alta, generador y cuenta', async ({ page }) => {
		await abrirPopup(page, {
			AUTH_ESTADO_SESION: SESION,
			VAULT_LISTAR: ITEMS,
			VAULT_REVELAR_SECRETO: { password: 'Tr0mb0n-azul-17', notes: 'Cambiar en enero.', totpSecret: 'JBSWY3DPEHPK3PXP' }
		});
		await expect(page.locator('#vista-desbloqueada')).toBeVisible();
		await expect(page.locator('#vista-detalle-item')).toBeVisible();
		const fallas = (await auditar(page)).map((v) => `bóveda + detalle: ${v}`);

		await page.locator('#boton-revelar-password').click();
		await expect(page.locator('#boton-revelar-password')).toHaveAttribute('aria-label', 'Ocultar contraseña');
		fallas.push(...(await auditar(page)).map((v) => `secreto revelado: ${v}`));

		await page.locator('#boton-nuevo').click();
		await expect(page.locator('#vista-form-recurso')).toBeVisible();
		fallas.push(...(await auditar(page)).map((v) => `alta: ${v}`));

		await page.locator('#boton-generar-password').click();
		await expect(page.locator('#boton-cerrar-generador')).toBeVisible();
		fallas.push(...(await auditar(page)).map((v) => `generador: ${v}`));
		await page.locator('#tab-modo-frase').click();
		fallas.push(...(await auditar(page)).map((v) => `generador (frase): ${v}`));
		await page.locator('#boton-cerrar-generador').click();

		await page.locator('#boton-cuenta').click();
		await expect(page.locator('#vista-cuenta')).toBeVisible();
		fallas.push(...(await auditar(page)).map((v) => `cuenta: ${v}`));
		expect(fallas).toEqual([]);
	});

	test('página: menú inline de autofill y barra de guardado', async ({ page }) => {
		await simularChrome(page, {
			AUTOFILL_BUSCAR: [
				{ id: 'r-1', nombre: 'Correo corporativo', usuario: 'ana.perez', uri: PAGINA_LOGIN },
				{ id: 'r-3', nombre: 'Correo (cuenta de soporte)', usuario: 'soporte', uri: PAGINA_LOGIN }
			],
			VAULT_REVELAR_SECRETO: { password: 'Tr0mb0n-azul-17' }
		});
		await servirExtension(page);
		await page.goto(PAGINA_LOGIN);
		await page.addScriptTag({ url: `${ORIGEN_EXTENSION}/content.js` });

		await page.locator('input[type="password"]').focus();
		const menu = page.locator('button', { hasText: 'Correo corporativo' });
		await expect(menu).toBeVisible();
		const fallas = (await auditar(page)).map((v) => `menú inline: ${v}`);

		// Teclado (WCAG 2.1.1): flechas para entrar y moverse, Escape vuelve
		// al campo sin reabrir el menú, Enter elige y rellena.
		const campo = page.locator('input[type="password"]');
		await page.keyboard.press('ArrowDown');
		await expect(menu).toBeFocused();
		await page.keyboard.press('ArrowDown');
		await expect(page.locator('button', { hasText: 'cuenta de soporte' })).toBeFocused();
		await page.keyboard.press('Escape');
		await expect(campo).toBeFocused();
		await expect(menu).toHaveCount(0);
		await campo.blur();
		await campo.focus();
		await expect(menu).toBeVisible();
		await page.keyboard.press('ArrowDown');
		await page.keyboard.press('Enter');
		await expect(campo).toHaveValue('Tr0mb0n-azul-17');
		await expect(page.locator('input[name="username"]')).toHaveValue('ana.perez');

		// Credencial nueva (otro usuario) → se ofrece guardarla.
		await page.keyboard.press('Escape');
		await page.locator('input[name="username"]').fill('ana.nueva');
		await page.locator('input[type="password"]').fill('otra-clave-de-prueba');
		await page.locator('form button[type="submit"]').click();
		await expect(page.getByRole('button', { name: 'Guardar' })).toBeVisible();
		fallas.push(...(await auditar(page)).map((v) => `barra de guardado: ${v}`));
		expect(fallas).toEqual([]);
	});
});
