<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// Layout minimalista (07-frontend-web.md §3): sin nav lateral, sin
	// bundle del panel de administración — es la primera carga que ve
	// cualquiera antes de autenticarse.
	//
	// Barra superior con logo + selector de idioma (no de tema — la paleta
	// de marca es fija, sin claro/oscuro alternativo en estas pantallas
	// todavía): mueve `preferencias.locale` directo, mismo store que
	// `/settings/preferences` guarda en disco — no hace falta sesión para
	// cambiar de idioma, y el cambio se ve reflejado de inmediato en toda
	// la UI porque `$t` (`$lib/i18n`) es un store derivado de éste.
	import type { Snippet } from 'svelte';
	import { preferencias } from '$lib/state/session';
	let { children }: { children: Snippet } = $props();

	function cambiarLocale(locale: 'es' | 'en') {
		preferencias.update((p) => ({ ...p, locale }));
	}
</script>

<div class="anon-shell">
	<header class="topbar">
		<div class="marca-anon">
			<img src="/ellkan-icon-mark.png" alt="Ellkan" width="32" height="32" />
			<span>Ellkan</span>
		</div>
		<div class="idioma-toggle">
			<button type="button" class:activo={$preferencias.locale === 'es'} onclick={() => cambiarLocale('es')}>
				Español
			</button>
			<button type="button" class:activo={$preferencias.locale === 'en'} onclick={() => cambiarLocale('en')}>
				English
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
	.idioma-toggle {
		display: flex;
		gap: var(--space-2);
	}
	.idioma-toggle button {
		background: none;
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-1) var(--space-3);
		font-size: var(--text-xs);
		color: var(--text-secondary);
		cursor: pointer;
	}
	.idioma-toggle button.activo {
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
