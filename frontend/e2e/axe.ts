// Autor: Athan Espinoza

// Lo común a las auditorías de accesibilidad (spec/14 punto 6.12, pendiente
// #66): axe con las reglas de WCAG 2.0/2.1/2.2 A y AA, y el tema guardado en
// las preferencias locales (mismo almacenamiento que la app).

import AxeBuilder from '@axe-core/playwright';
import type { Page } from '@playwright/test';

export const TEMAS = ['dark', 'light'] as const;
export type Tema = (typeof TEMAS)[number];

export async function auditar(page: Page, incluir?: string): Promise<string[]> {
	// Sin transiciones a medias (un modal que aparece con fundido daría
	// contrastes de colores mezclados que nadie ve quietos).
	await page
		.waitForFunction(() => document.getAnimations().every((a) => a.playState !== 'running' || a.effect?.getTiming().iterations === Infinity), undefined, {
			timeout: 5_000
		})
		.catch(() => {});
	let builder = new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa']);
	if (incluir) builder = builder.include(incluir);
	const resultado = await builder.analyze();
	return resultado.violations.map(
		(v) => `${v.id} (${v.impact}): ${v.help}\n    ${v.nodes.map((n) => `${n.target.join(' ')} — ${n.failureSummary?.split('\n').slice(1).join(' ')}`).join('\n    ')}`
	);
}

export async function fijarTema(page: Page, tema: Tema): Promise<void> {
	await page.addInitScript((t) => {
		localStorage.setItem('ellkan:preferencias', JSON.stringify({ locale: 'es', theme: t, clipboardClearMinutes: 1, autoLockMinutes: 15 }));
	}, tema);
}
