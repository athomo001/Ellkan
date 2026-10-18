// Autor: Athan Espinoza

// spec/14 punto 6.12: auditoría automática de accesibilidad (axe) sobre las
// pantallas reales. Usa el Chrome ya instalado en la máquina (`channel:
// 'chrome'`), sin descargar navegadores aparte; en CI, cambiar a
// `npx playwright install chromium` y quitar `channel`.
//
// Uso: `pnpm test:a11y` (levanta `vite dev` solo).

import { defineConfig } from '@playwright/test';

const PUERTO = 5179;

export default defineConfig({
	testDir: 'e2e',
	timeout: 60_000,
	reporter: 'list',
	use: {
		baseURL: `http://localhost:${PUERTO}`,
		channel: 'chrome',
		headless: true
	},
	webServer: {
		command: `pnpm exec vite dev --port ${PUERTO} --strictPort`,
		url: `http://localhost:${PUERTO}/login`,
		reuseExistingServer: true,
		timeout: 120_000
	}
});
