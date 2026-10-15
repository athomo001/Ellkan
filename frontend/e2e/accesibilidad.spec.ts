// Autor: Athan Espinoza

// spec/14 punto 6.12 (objetivo WCAG 2.2 AA): axe sobre las pantallas sin
// sesión, en los dos temas. Falla con cualquier violación de las reglas de
// WCAG 2.0/2.1/2.2 A y AA. Las pantallas con sesión necesitan un backend con
// datos y quedan para cuando haya E2E completos.

import { test, expect, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

const PANTALLAS = [
	{ nombre: 'login', ruta: '/login' },
	{ nombre: 'registro', ruta: '/register' },
	{ nombre: 'recuperar', ruta: '/recover' },
	{ nombre: 'link externo', ruta: '/s/00000000-0000-0000-0000-000000000000' }
];

const TEMAS = ['dark', 'light'] as const;

async function auditar(page: Page): Promise<string[]> {
	const resultado = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']).analyze();
	return resultado.violations.map(
		(v) => `${v.id} (${v.impact}): ${v.help}\n    ${v.nodes.map((n) => `${n.target.join(' ')} — ${n.failureSummary?.split('\n').slice(1).join(' ')}`).join('\n    ')}`
	);
}

for (const tema of TEMAS) {
	for (const { nombre, ruta } of PANTALLAS) {
		test(`${nombre} (${tema}) sin violaciones WCAG 2.2 AA`, async ({ page }) => {
			// El tema sale de las preferencias guardadas (mismo almacenamiento que la app).
			await page.addInitScript((t) => {
				localStorage.setItem(
					'ellkan:preferencias',
					JSON.stringify({ locale: 'es', theme: t, clipboardClearMinutes: 1, autoLockMinutes: 15 })
				);
			}, tema);
			await page.goto(ruta);
			await page.waitForLoadState('networkidle').catch(() => {});
			await expect(page.locator('main, form, h1').first()).toBeVisible();
			expect(await auditar(page)).toEqual([]);
		});
	}
}
