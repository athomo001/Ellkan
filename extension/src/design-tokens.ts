// Autor: Athan Espinoza

// Sistema de diseño compartido con el frontend web (F-30, spec 06 §5) —
// **fuente única de los valores de token** para la extensión. Los valores
// son los de la paleta OSCURA de `frontend/src/lib/styles/tokens.css` (la
// extensión es dark-only), copiados literalmente acá porque un content
// script / popup MV3 no puede importar el `.css` de SvelteKit sin arrastrar
// su runtime (spec 06 §5, "SvelteKit no es importable en un content
// script/popup"). Por eso la spec pide tokens compartidos, **no**
// componentes Svelte reales.
//
// Consumidores:
//  - `content/index.ts` (menú de autofill + notification bar) importa `TOKENS`.
//  - `popup/styles.css` declara los mismos valores como custom properties
//    `--ellkan-*` (con un comentario que apunta acá como canónico).
//
// Si cambia un color de marca: se cambia en `tokens.css` (web) y acá, en el
// mismo commit — igual criterio que el resto del código compartido.

export const TOKENS = {
	/** `--bg-base` de la web. */
	fondo: '#102335',
	/** `--bg-raised`. */
	fondoTarjeta: '#16293c',
	/** `--bg-overlay`. */
	fondoOverlay: '#1c3245',
	/** `--border-color`. */
	borde: '#26405a',
	/** `--text-primary`. */
	texto: '#f8f8f8',
	/** `--text-secondary`. */
	textoSecundario: '#a9b8c7',
	/** `--text-muted`. */
	textoMudo: '#6f8298',
	/** `--color-teal` (`--accent-primary`). */
	teal: '#187890',
	/** `--accent-primary-hover`. */
	tealHover: '#1e8ba6',
	/** `--color-gold` (`--accent-secondary`). */
	dorado: '#e0b860',
	/** `--danger`. */
	error: '#e2695f',
	/** `--success`. */
	exito: '#4caf7d',
	/** `--warning`. */
	advertencia: '#e0b860'
} as const;

export type Tokens = typeof TOKENS;
