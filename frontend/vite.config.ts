import adapter from '@sveltejs/adapter-static';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

// El backend Axum sirve el build compilado como archivos estáticos (un solo
// binario, un solo proceso — docs/techStack.md) — `adapter-static` con
// fallback SPA, porque el routing en tres capas (anónimo/autenticado/admin,
// spec 07-frontend-web.md sección 3) se resuelve client-side contra sesión,
// no vía prerender por ruta.
export default defineConfig({
	plugins: [
		sveltekit({
			compilerOptions: {
				runes: ({ filename }) =>
					filename.split(/[/\\]/).includes('node_modules') ? undefined : true
			},
			adapter: adapter({
				pages: 'build',
				assets: 'build',
				fallback: 'index.html',
				strict: false
			}),
			// `adapter-static` no puede setear headers HTTP — el CSP real que
			// importa lo sigue poniendo Axum (`backend/src/lib.rs`, incluye
			// `frame-ancestors`, que un <meta> no puede expresar por spec).
			// Pero el propio bootstrap inline que SvelteKit inyecta en
			// `index.html` (el `<script>` que hace `Promise.all([import(...)])`
			// para arrancar la app) necesita quedar permitido por `script-src`
			// — sin `'unsafe-inline'` (que no vamos a usar) hace falta su hash
			// exacto, que cambia con cada build (los nombres de archivo
			// hasheados cambian). `csp: { mode: 'hash' }` hace que SvelteKit
			// calcule ese hash en cada build y lo inyecte solo en un <meta
			// http-equiv="Content-Security-Policy">, sin tocar el header real.
			csp: {
				mode: 'hash',
				directives: {
					'script-src': ['self', 'wasm-unsafe-eval']
				}
			}
		})
	],
	// `ellkan_crypto.wasm` se sirve como asset — nunca reinterpretado como
	// módulo JS por el dev server.
	assetsInclude: ['**/*.wasm'],
	// Sólo desarrollo: en producción Axum sirve el build compilado y las
	// rutas de API desde el mismo origen (ver comentario arriba), así que
	// `api/client.ts::baseUrl()` puede seguir devolviendo `''`. El proxy
	// evita levantar un CORS aparte sólo para `pnpm dev`.
	server: {
		proxy: {
			'/auth': 'http://localhost:8080',
			'/resources': 'http://localhost:8080',
			'/admin': 'http://localhost:8080',
			'/me': 'http://localhost:8080',
			'/groups': 'http://localhost:8080',
			'/folders': 'http://localhost:8080',
			'/tags': 'http://localhost:8080',
			'/metadata-keys': 'http://localhost:8080',
			'/scim': 'http://localhost:8080',
			'/account-recovery': 'http://localhost:8080',
			'/external-shares': 'http://localhost:8080',
			'/export-policy': 'http://localhost:8080',
			'/export-events': 'http://localhost:8080',
			'/users': 'http://localhost:8080',
			'/healthz': 'http://localhost:8080'
		}
	}
});
