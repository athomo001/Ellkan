// Autor: Athan Espinoza

// spec/14 punto 6.12: auditoría automática de accesibilidad (axe) sobre las
// pantallas reales. En local usa el Chrome ya instalado en la máquina
// (`channel: 'chrome'`), sin descargar navegadores aparte; en el CI
// (`CI=true`, QA-13 / pendiente #102) usa el Chromium de Playwright
// (`playwright install --with-deps chromium`).
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
		...(process.env.CI ? {} : { channel: 'chrome' }),
		headless: true,
		// Sin animaciones: axe no puede auditar un modal a mitad de su fundido
		// (en el runner lento del CI daba contrastes mezclados que nadie ve).
		reducedMotion: 'reduce'
	},
	webServer: {
		command: `pnpm exec vite dev --port ${PUERTO} --strictPort`,
		url: `http://localhost:${PUERTO}/login`,
		reuseExistingServer: true,
		timeout: 120_000
	}
});
