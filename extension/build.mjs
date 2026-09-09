// Autor: Athan Espinoza

// Build multi-navegador de la extensión (spec 06 §1) — no usamos un solo
// `vite build` porque el service worker y el content script tienen que ser
// bundles IIFE autocontenidos (sin `import`, compatibles con el modelo de
// ejecución de content scripts en los tres navegadores), mientras que el
// popup es una página HTML normal que sí puede usar ESM. Rollup no permite
// mezclar formatos en una sola invocación con múltiples entradas, así que
// corremos `vite.build()` tres veces contra el mismo `dist/`.

import { build } from 'vite';
import { writeFileSync, mkdirSync, cpSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, resolve } from 'node:path';
import { resolverManifest, manifestFuente } from './manifest-resolve.mjs';

const raiz = dirname(fileURLToPath(import.meta.url));
const dist = resolve(raiz, 'dist');
const browser = (process.env.BROWSER ?? 'chrome').toLowerCase();

if (!['chrome', 'firefox', 'safari'].includes(browser)) {
	throw new Error(`BROWSER debe ser chrome|firefox|safari, no "${browser}"`);
}

// `resolverManifest` (spec 06 §1) vive en `manifest-resolve.mjs` para
// compartirlo con `self-check.ts` (test de `frame-ancestors`).

mkdirSync(dist, { recursive: true });

const manifestResuelto = resolverManifest(manifestFuente(), browser);
writeFileSync(resolve(dist, 'manifest.json'), JSON.stringify(manifestResuelto, null, 2));

cpSync(resolve(raiz, 'public'), dist, { recursive: true });

// El wasm-bindgen glue resuelve `import.meta.url` sólo si `init()` no recibe
// argumento (ver comentario en `src/background/wasm.ts`) — como siempre le
// pasamos una URL explícita, ese binario tiene que existir de verdad en
// `dist/` bajo el nombre que `chrome.runtime.getURL('ellkan_crypto_bg.wasm')`
// espera. Copia directa, no depende de que Rollup detecte el patrón bajo
// el bundle IIFE (no lo detecta).
cpSync(resolve(raiz, '../frontend/src/lib/wasm/ellkan_crypto_bg.wasm'), resolve(dist, 'ellkan_crypto_bg.wasm'));

const comun = {
	root: raiz,
	define: {
		__ELLKAN_BROWSER__: JSON.stringify(browser)
	},
	build: {
		outDir: dist,
		emptyOutDir: false,
		minify: false,
		assetsInclude: ['**/*.wasm']
	}
};

// Sólo para los bundles IIFE (background/content): silencia el warning
// `EMPTY_IMPORT_META` de Rollup en `ellkan_crypto.js` — la rama que usa
// `import.meta.url` ahí es inalcanzable en runtime porque `wasm.ts` siempre
// le pasa una URL explícita a `init()` (ver ese archivo). Confirmado, no
// silenciado a ciegas. No se aplica al build del popup (si algún día usa
// `import.meta` de verdad, no hay que pisárselo).
const defineIife = { ...comun.define, 'import.meta': '{}' };

// Service worker — IIFE autocontenido, un solo archivo, sin `import` externo.
await build({
	...comun,
	define: defineIife,
	build: {
		...comun.build,
		lib: {
			entry: resolve(raiz, 'src/background/index.ts'),
			name: 'EllkanBackground',
			formats: ['iife'],
			fileName: () => 'background.js'
		}
	}
});

// Content script — mismo criterio: IIFE, un solo archivo.
await build({
	...comun,
	define: defineIife,
	build: {
		...comun.build,
		lib: {
			entry: resolve(raiz, 'src/content/index.ts'),
			name: 'EllkanContent',
			formats: ['iife'],
			fileName: () => 'content.js'
		}
	}
});

// Popup — página HTML normal, sí puede usar ESM. `root` apunta a su propia
// carpeta para que `dist/popup/index.html` quede en la ruta que el
// manifest espera (`action.default_popup`), sin arrastrar la estructura
// `src/popup/...` completa al output.
await build({
	...comun,
	// Sin esto, Vite emite rutas de asset absolutas (`/assets/...`) asumiendo
	// que la página se sirve desde la raíz de un dominio. El popup vive en
	// `chrome-extension://<id>/popup/index.html`, así que esa ruta absoluta
	// resuelve a `chrome-extension://<id>/assets/...` (404 — los assets
	// reales quedan en `.../popup/assets/...`): ni el JS ni el CSS cargaban
	// nunca, por eso el popup se veía sin ningún estilo.
	base: './',
	root: resolve(raiz, 'src/popup'),
	build: {
		...comun.build,
		outDir: resolve(dist, 'popup'),
		// A diferencia de `comun.build` (que necesita `false` para no borrar
		// `background.js`/`content.js` ya generados en este mismo `dist/`),
		// `dist/popup/` es exclusivo de este paso — sin esto, cada rebuild
		// acumulaba los `assets/index-*.{js,css}` con hash de la vez anterior
		// (huérfanos, `index.html` sólo referencia los últimos), inflando el
		// `.zip`/`.crx`/`.xpi` empaquetado con cada iteración.
		emptyOutDir: true
	}
});

console.log(`Extensión (${browser}) construida en ${dist}`);
