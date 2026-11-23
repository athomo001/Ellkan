// Autor: Athan Espinoza

// Pendiente #66 (WCAG 2.2 AA en lo que faltaba): axe sobre las pantallas con
// sesión, en los dos temas. Sin backend: un servidor simulado
// (`servidor-simulado.ts`) responde la API, y el login es real por la UI —
// el blob de la clave privada se sella en Node con el mismo WASM, así que el
// navegador desbloquea de verdad (Argon2id incluido) y las pantallas que
// necesitan claves se ven como en uso. Se navega sin recargar (las claves
// viven sólo en memoria).
//
// La app de escritorio es este mismo frontend dentro de WebView2 (Chromium):
// con el puente de Tauri simulado (`instalarEscritorio`) entra en modo
// escritorio y se auditan también sus pantallas propias (sincronización,
// ajustes de escritorio). Lo nativo (bandeja, diálogos del SO) queda fuera:
// no es HTML.

import { test, expect, type Page } from '@playwright/test';
import { auditar, fijarTema, TEMAS } from './axe';
import { ServidorSimulado } from './servidor-simulado';

// Todas las rutas de `(app)` en la web (las de escritorio, abajo).
const PANTALLAS = [
	'/vault',
	'/health',
	'/settings/profile',
	'/settings/avatar',
	'/settings/security',
	'/settings/keys',
	'/settings/passphrase',
	'/settings/preferences',
	'/settings/emergency',
	'/settings/external-shares',
	'/settings/token',
	'/onboarding/recovery-kit',
	'/admin',
	'/admin/users',
	'/admin/groups',
	'/admin/roles',
	'/admin/audit-log',
	'/admin/reports',
	'/admin/system-status',
	'/admin/metadata-keys',
	'/admin/directory-sync',
	'/admin/scim',
	'/admin/smtp',
	'/admin/sso',
	'/admin/policies/account-recovery',
	'/admin/policies/emergency-access',
	'/admin/policies/export',
	'/admin/policies/external-share',
	'/admin/policies/legal',
	'/admin/policies/mfa',
	'/admin/policies/password',
	'/admin/policies/retention',
	'/admin/policies/self-registration'
];

// Lo que muestra el menú en modo escritorio (sin administración ni contactos
// de emergencia: es de un solo usuario).
const PANTALLAS_ESCRITORIO = [
	'/vault',
	'/health',
	'/settings/profile',
	'/settings/avatar',
	'/settings/keys',
	'/settings/passphrase',
	'/settings/token',
	'/settings/preferences',
	'/settings/security',
	'/settings/sync',
	'/settings/desktop'
];

/** Navegación del lado del cliente (SvelteKit intercepta el click en un
 * `<a>`): un `page.goto` recargaría y perdería las claves. */
async function navegar(page: Page, ruta: string): Promise<void> {
	await page.evaluate((r) => {
		const a = document.createElement('a');
		a.href = r;
		document.body.appendChild(a);
		a.click();
		a.remove();
	}, ruta);
	await page.waitForURL((u) => u.pathname === ruta.split('?')[0]);
	await page.waitForLoadState('networkidle').catch(() => {});
	await expect(page.locator('main h1').first(), `${ruta} abre con un h1`).toBeVisible();
	// Terminan de cargar los datos (los "Cargando…" se reemplazan).
	await expect(page.getByText(/^(Cargando|Loading)…?$/), `${ruta} termina de cargar`).toHaveCount(0, { timeout: 10_000 });
}

/** Login real por la UI; devuelve las violaciones de la pantalla de login
 * (en escritorio cambia: no ofrece registrarse ni SSO). */
async function entrar(page: Page, servidor: ServidorSimulado, tema: (typeof TEMAS)[number]): Promise<string[]> {
	await fijarTema(page, tema);
	await servidor.instalar(page);
	await page.goto('/login');
	// Hidratada (si no, el submit es el nativo del formulario).
	await page.waitForLoadState('networkidle');
	const enLogin = await auditar(page);
	await page.locator('input[type="email"]').fill(servidor.email);
	await page.locator('input[autocomplete="current-password"]').fill(servidor.passphrase);
	await page.locator('form button[type="submit"]').click();
	await page.waitForURL('**/vault', { timeout: 60_000 });
	await expect(page.locator('main h1').first()).toBeVisible();
	return enLogin.map((v) => `/login: ${v}`);
}

/** Los estados del vault donde más se trabaja: el detalle de un recurso
 * (con el secreto descifrado bajo demanda) y el alta. */
async function estadosDelVault(page: Page): Promise<string[]> {
	const fallas: string[] = [];
	await navegar(page, '/vault');
	await page.getByText('Correo corporativo').first().click();
	await page.waitForLoadState('networkidle').catch(() => {});
	for (const v of await auditar(page)) fallas.push(`/vault (detalle): ${v}`);
	await page.getByRole('button', { name: 'Nuevo recurso' }).first().click();
	await expect(page.getByRole('heading', { name: 'Nuevo recurso' }).first()).toBeVisible();
	for (const v of await auditar(page)) fallas.push(`/vault (nuevo): ${v}`);
	return fallas;
}

async function recorrer(page: Page, rutas: string[]): Promise<string[]> {
	const fallas: string[] = [];
	for (const ruta of rutas) {
		await navegar(page, ruta);
		for (const v of await auditar(page)) fallas.push(`${ruta}: ${v}`);
	}
	return fallas;
}

for (const tema of TEMAS) {
	test.describe(`con sesión (${tema})`, () => {
		test.describe.configure({ timeout: 600_000 });

		test(`web: todas las pantallas sin violaciones WCAG 2.2 AA`, async ({ page }) => {
			const servidor = await ServidorSimulado.crear(tema);
			const fallas = await entrar(page, servidor, tema);
			fallas.push(...(await recorrer(page, PANTALLAS)));
			fallas.push(...(await estadosDelVault(page)));
			expect(servidor.erroresDePagina, 'la app no debería romperse con el servidor simulado').toEqual([]);
			expect(fallas).toEqual([]);
		});

		test(`escritorio: login y pantallas sin violaciones WCAG 2.2 AA`, async ({ page }) => {
			const servidor = await ServidorSimulado.crear(tema);
			await servidor.instalarEscritorio(page);
			const fallas = await entrar(page, servidor, tema);
			fallas.push(...(await recorrer(page, PANTALLAS_ESCRITORIO)));
			fallas.push(...(await estadosDelVault(page)));
			expect(servidor.erroresDePagina, 'la app no debería romperse con el servidor simulado').toEqual([]);
			expect(fallas).toEqual([]);
		});
	});
}
