<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// Diálogo genérico reusable — antes cada flujo (compartir, exportar, etc.)
	// vivía como panel inline empujando el resto de la página hacia abajo,
	// mucho más espacio en pantalla que lo que pide la referencia de
	// Passbolt (un modal compacto, centrado, que no reorganiza el resto del
	// layout). Cierra con click en el fondo, Escape, o el botón X.
	import type { Snippet } from 'svelte';
	import { fade, scale } from 'svelte/transition';

	let {
		titulo,
		subtitulo,
		onCerrar,
		children
	}: { titulo: string; subtitulo?: string; onCerrar: () => void; children: Snippet } = $props();

	function onKeydown(e: KeyboardEvent) {
		if (e.key === 'Escape') onCerrar();
	}
</script>

<svelte:window onkeydown={onKeydown} />

<div class="overlay" role="presentation" onclick={onCerrar} transition:fade={{ duration: 120 }}>
	<!-- svelte-ignore a11y_no_static_element_interactions -->
	<!-- svelte-ignore a11y_click_events_have_key_events -->
	<div
		class="panel"
		role="dialog"
		aria-modal="true"
		aria-label={titulo}
		tabindex="-1"
		onclick={(e) => e.stopPropagation()}
		transition:scale={{ duration: 150, start: 0.96, opacity: 0 }}
	>
		<div class="cabecera">
			<div>
				<h2>{titulo}{#if subtitulo}<span class="subtitulo">{subtitulo}</span>{/if}</h2>
			</div>
			<button type="button" class="cerrar" onclick={onCerrar} aria-label="Cerrar">✕</button>
		</div>
		<div class="contenido">
			{@render children()}
		</div>
	</div>
</div>

<style>
	.overlay {
		position: fixed;
		inset: 0;
		z-index: 200;
		display: flex;
		align-items: center;
		justify-content: center;
		background: color-mix(in srgb, var(--bg-base) 75%, transparent);
		backdrop-filter: blur(6px);
		padding: var(--space-4);
	}
	.panel {
		width: 100%;
		max-width: 26rem;
		max-height: 85vh;
		overflow-y: auto;
		background: var(--bg-raised);
		border: 1px solid var(--border-color);
		border-radius: 12px;
		/* `--space-6` (24px) — mismo padding que el `p-6` de shadcn/ui Dialog,
		   valor real de referencia, no a ojo. Bug real encontrado acá: esto
		   decía `var(--space-5)`, un token que no existe en la escala
		   (`--space-1..4, 6, 8`, sin 5) — el padding quedaba inválido y
		   computaba a 0, el panel entero pegado al borde sin aire. */
		padding: var(--space-6);
		box-shadow:
			0 20px 48px -12px color-mix(in srgb, var(--bg-base) 70%, transparent),
			0 0 0 1px color-mix(in srgb, var(--accent-primary) 8%, transparent);
	}
	.cabecera {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: var(--space-3);
		margin-bottom: var(--space-4);
	}
	h2 {
		margin: 0;
		font-size: var(--text-lg);
		font-weight: 700;
		line-height: 1.3;
		color: var(--text-primary);
	}
	.subtitulo {
		display: block;
		margin-top: var(--space-1);
		font-size: var(--text-sm);
		font-weight: 400;
		color: var(--text-muted);
	}
	.contenido {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
	}
	.cerrar {
		display: flex;
		align-items: center;
		justify-content: center;
		width: 1.75rem;
		height: 1.75rem;
		background: var(--bg-overlay);
		border: 1px solid transparent;
		border-radius: 50%;
		color: var(--text-secondary);
		cursor: pointer;
		font-size: var(--text-sm);
		line-height: 1;
		flex-shrink: 0;
		transition: all 0.12s ease;
	}
	.cerrar:hover {
		color: var(--text-primary);
		border-color: var(--border-color);
		background: var(--bg-base);
	}
</style>
