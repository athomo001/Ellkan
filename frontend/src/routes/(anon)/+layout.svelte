<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// Layout minimalista (07-frontend-web.md §3): sin nav lateral, sin
	// bundle del panel de administración — es la primera carga que ve
	// cualquiera antes de autenticarse.
	//
	// Barra superior con logo + selector de idioma + toggle de tema: mueve
	// `preferencias.locale`/`.theme` directo, mismo store que
	// `/settings/preferences` guarda en disco — no hace falta sesión para
	// cambiar ninguno de los dos, y el cambio se ve reflejado de inmediato
	// (`$t` es un store derivado de `preferencias`, y `aplicarTema` ya se
	// llama desde el layout raíz en cada cambio, en toda ruta).
	import type { Snippet } from 'svelte';
	import { preferencias } from '$lib/state/session';
	import { alternarTema } from '$lib/api/preferences';
	import { t } from '$lib/i18n';
	let { children }: { children: Snippet } = $props();

	function alternarIdioma() {
		preferencias.update((p) => ({ ...p, locale: p.locale === 'es' ? 'en' : 'es' }));
	}
</script>

<div class="anon-shell">
	<header class="topbar">
		<div class="marca-anon">
			<img src="/ellkan-icon-mark.png" alt="Ellkan" width="32" height="32" />
			<span>Ellkan</span>
		</div>
		<div class="controles">
			<button type="button" class="toggle-tema" onclick={(e) => alternarTema($preferencias.theme, e)} title={$t.appShell.cambiarTema}>
				{#if $preferencias.theme === 'light'}
					<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" width="16" height="16">
						<path stroke-linecap="round" stroke-linejoin="round" d="M12 3v2.25m6.364.386-1.591 1.591M21 12h-2.25m-.386 6.364-1.591-1.591M12 18.75V21m-4.773-4.227-1.591 1.591M3 12h2.25m-.386-6.364 1.591 1.591M12 7.5a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9Z" />
					</svg>
				{:else}
					<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" width="16" height="16">
						<path stroke-linecap="round" stroke-linejoin="round" d="M21.752 15.002A9.72 9.72 0 0 1 18 15.75c-5.385 0-9.75-4.365-9.75-9.75 0-1.33.266-2.597.748-3.752A9.753 9.753 0 0 0 3 11.25C3 16.635 7.365 21 12.75 21a9.753 9.753 0 0 0 9.002-5.998Z" />
					</svg>
				{/if}
			</button>
			<button
				type="button"
				class="toggle-idioma"
				onclick={alternarIdioma}
				title={$preferencias.locale === 'es' ? 'Switch to English' : 'Cambiar a Español'}
			>
				{$preferencias.locale}
			</button>
		</div>
	</header>
	<main class="contenido">
		<div class="marco">
			{@render children()}
		</div>
	</main>
</div>

<style>
	.anon-shell {
		min-height: 100vh;
		display: flex;
		flex-direction: column;
		background: var(--bg-base);
	}
	.topbar {
		display: flex;
		align-items: center;
		justify-content: space-between;
		padding: var(--space-4) var(--space-6);
	}
	.marca-anon {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.marca-anon img {
		display: block;
		border-radius: var(--radius-sm);
	}
	.marca-anon span {
		font-size: var(--text-lg);
		font-weight: 700;
		background: var(--gradient-brand);
		-webkit-background-clip: text;
		background-clip: text;
		color: transparent;
	}
	.controles {
		display: flex;
		align-items: center;
		gap: var(--space-3);
	}
	.toggle-tema {
		display: flex;
		align-items: center;
		justify-content: center;
		background: none;
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-1);
		color: var(--text-secondary);
		cursor: pointer;
	}
	.toggle-tema:hover {
		color: var(--text-primary);
		border-color: var(--accent-primary);
	}
	.toggle-idioma {
		background: none;
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-1) var(--space-2);
		font-size: var(--text-xs);
		font-weight: 700;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		color: var(--text-secondary);
		cursor: pointer;
	}
	.toggle-idioma:hover {
		color: var(--text-primary);
		border-color: var(--accent-primary);
	}
	.contenido {
		flex: 1;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: var(--space-6);
	}
	.marco {
		width: 100%;
		max-width: 24rem;
	}
</style>
