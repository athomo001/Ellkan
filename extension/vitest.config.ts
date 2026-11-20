// Autor: Athan Espinoza

// QA-14 (pendiente #103): tests unitarios de la extensión, en Node.
import { defineConfig } from 'vitest/config';

export default defineConfig({
	test: {
		include: ['src/**/*.test.ts'],
		environment: 'node'
	}
});
