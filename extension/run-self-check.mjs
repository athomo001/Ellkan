// Autor: Athan Espinoza

// Empaqueta un `self-check*.ts` con Vite (resuelve imports sin extensión,
// igual que el build real) y lo corre con Node — `node self-check.ts`
// directo no alcanza porque la resolución ESM nativa de Node exige
// extensión explícita en cada import relativo, a diferencia de
// `moduleResolution: "bundler"`.
//
// Uso: node run-self-check.mjs [self-check.ts | self-check-storage.ts]
// Sin argumento, corre los dos.

import { build } from 'vite';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { rmSync } from 'node:fs';

const raiz = dirname(fileURLToPath(import.meta.url));
const entradas = process.argv[2] ? [process.argv[2]] : ['self-check.ts', 'self-check-storage.ts'];

for (const entrada of entradas) {
	const nombre = entrada.replace(/\.ts$/, '');
	const salida = resolve(raiz, `.${nombre}-out`);

	await build({
		root: raiz,
		logLevel: 'warn',
		build: {
			outDir: salida,
			emptyOutDir: true,
			minify: false,
			ssr: true,
			lib: {
				entry: resolve(raiz, entrada),
				formats: ['es'],
				fileName: () => `${nombre}.mjs`
			}
		}
	});

	try {
		console.log(`--- ${entrada} ---`);
		// Vite en modo `ssr` ignora `fileName` y siempre nombra el entry `<name>.js`.
		execFileSync('node', [resolve(salida, `${nombre}.js`)], { stdio: 'inherit' });
	} finally {
		rmSync(salida, { recursive: true, force: true });
	}
}
