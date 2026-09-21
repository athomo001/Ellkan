<!-- Autor: Athan Espinoza -->
<script lang="ts">
	import type { Snippet } from 'svelte';

	type Variante = 'primary' | 'secondary' | 'ghost' | 'danger';

	let {
		variant = 'secondary',
		type = 'button',
		disabled = false,
		loading = false,
		onclick,
		children
	}: {
		variant?: Variante;
		type?: 'button' | 'submit';
		disabled?: boolean;
		loading?: boolean;
		onclick?: (e: MouseEvent) => void;
		children: Snippet;
	} = $props();
</script>

<button
	class="btn btn-{variant}"
	{type}
	disabled={disabled || loading}
	aria-busy={loading}
	{onclick}
>
	{#if loading}<span class="spinner" aria-hidden="true"></span>{/if}
	{@render children()}
</button>

<style>
	.btn {
		display: inline-flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-2) var(--space-4);
		border-radius: var(--radius-sm);
		border: 1px solid transparent;
		font-weight: 500;
		line-height: 1.2;
		/* Hallazgo real de uso (ventana angosta de escritorio): sin esto, un
		   botón dentro de una fila flex apretada (ej. `.botones` en el
		   Vault con el panel de detalle abierto) se achica por debajo del
		   ancho de su propio texto y la etiqueta se parte en 2 líneas — feo
		   y nada obvio de detectar sin probar en una ventana angosta de
		   verdad. El botón entero debe mantenerse de una pieza; si no
		   entra, que el contenedor lo mande a la siguiente línea, no que el
		   texto se parta adentro. */
		white-space: nowrap;
		flex-shrink: 0;
		transition:
			background-color 0.15s,
			border-color 0.15s,
			opacity 0.15s;
	}
	.btn:disabled {
		opacity: 0.55;
		cursor: not-allowed;
	}

	/* CTA primario: único lugar además del logo/nav activo donde el degradé
	   de marca es aceptable (01-propuesta-tecnica.md §2.5). */
	.btn-primary {
		background: var(--gradient-brand, var(--accent-primary));
		color: #06131d;
		font-weight: 600;
	}
	.btn-primary:hover:not(:disabled) {
		filter: brightness(1.08);
	}

	.btn-secondary {
		background: var(--bg-overlay);
		border-color: var(--border-color);
		color: var(--text-primary);
	}
	.btn-secondary:hover:not(:disabled) {
		border-color: var(--accent-primary);
	}

	.btn-ghost {
		background: transparent;
		color: var(--text-secondary);
	}
	.btn-ghost:hover:not(:disabled) {
		background: var(--bg-overlay);
		color: var(--text-primary);
	}

	.btn-danger {
		background: transparent;
		border-color: var(--danger);
		color: var(--danger);
	}
	.btn-danger:hover:not(:disabled) {
		background: var(--danger);
		color: #fff;
	}

	.spinner {
		width: 0.9em;
		height: 0.9em;
		border: 2px solid currentColor;
		border-right-color: transparent;
		border-radius: 50%;
		animation: spin 0.6s linear infinite;
	}
	@keyframes spin {
		to {
			transform: rotate(360deg);
		}
	}
</style>
