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
	assetsInclude: ['**/*.wasm']
});
