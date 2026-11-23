// Autor: Athan Espinoza

// spec/14 punto 6.12 (objetivo WCAG 2.2 AA): axe sobre las pantallas sin
// sesión, en los dos temas. Falla con cualquier violación de las reglas de
// WCAG 2.0/2.1/2.2 A y AA. Las pantallas con sesión, en
// `accesibilidad-sesion.spec.ts`; el popup y el menú inline de la extensión,
// en `accesibilidad-extension.spec.ts`.

import { test, expect } from '@playwright/test';
import { auditar, fijarTema, TEMAS } from './axe';

const PANTALLAS = [
	{ nombre: 'login', ruta: '/login' },
	{ nombre: 'registro', ruta: '/register' },
	{ nombre: 'recuperar', ruta: '/recover' },
	{ nombre: 'recuperación con aprobación de admins', ruta: '/recover/admin-approval' },
	{ nombre: 'link externo', ruta: '/s/00000000-0000-0000-0000-000000000000' }
];

for (const tema of TEMAS) {
	for (const { nombre, ruta } of PANTALLAS) {
		test(`${nombre} (${tema}) sin violaciones WCAG 2.2 AA`, async ({ page }) => {
			await fijarTema(page, tema);
			await page.goto(ruta);
			await page.waitForLoadState('networkidle').catch(() => {});
			await expect(page.locator('main, form, h1').first()).toBeVisible();
			expect(await auditar(page)).toEqual([]);
		});
	}
}

// Pendiente #109: el registro de la primera cuenta muestra el aviso y el campo
// del token de instalación. Se simula la respuesta del servidor.
for (const tema of TEMAS) {
	test(`registro con token de instalación (${tema}) sin violaciones WCAG 2.2 AA`, async ({ page }) => {
		await fijarTema(page, tema);
		await page.route('**/auth/setup-status', (ruta) => ruta.fulfill({ json: { setup_token_required: true } }));
		await page.goto('/register');
		await expect(page.getByRole('note')).toBeVisible();
		expect(await auditar(page)).toEqual([]);
	});
}
