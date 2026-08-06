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
			})
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
			'/users': 'http://localhost:8080',
			'/healthz': 'http://localhost:8080'
		}
	}
});
