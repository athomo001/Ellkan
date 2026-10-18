<!-- Autor: Athan Espinoza -->
<!--
	Barra de progreso para operaciones largas (cargar el vault, importar un
	respaldo). Pedido 2026-10-17: con 139+ claves sólo se veía "Cargando…"
	durante decenas de segundos y después, a veces, "Too Many Requests" — la
	barra muestra "N de M" y qué clave va, para que se vea que avanza.
-->
<script lang="ts">
	let {
		hechos,
		total,
		titulo,
		detalle
	}: {
		hechos: number;
		/** 0 = todavía no se sabe cuántos son: barra indeterminada. */
		total: number;
		/** Ej. "Cargando claves" / "Importando". */
		titulo: string;
		/** Ej. el nombre de la última clave procesada. Opcional. */
		detalle?: string;
	} = $props();

	const porcentaje = $derived(total > 0 ? Math.min(100, Math.round((hechos / total) * 100)) : 0);
</script>

<div class="progreso" role="status" aria-live="polite">
	<div class="fila">
		<span class="titulo">{titulo}</span>
		{#if total > 0}
			<span class="cuenta">{hechos} / {total} · {porcentaje}%</span>
		{/if}
	</div>
	<div
		class="pista"
		role="progressbar"
		aria-valuemin="0"
		aria-valuemax={total || undefined}
		aria-valuenow={total > 0 ? hechos : undefined}
		aria-label={titulo}
	>
		<div class="relleno" class:indeterminado={total === 0} style:width={total > 0 ? `${porcentaje}%` : undefined}></div>
	</div>
	{#if detalle}
		<p class="detalle" title={detalle}>{detalle}</p>
	{/if}
</div>

<style>
	.progreso {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		padding: var(--space-3) 0;
	}
	.fila {
		display: flex;
		justify-content: space-between;
		gap: var(--space-3);
		font-size: var(--text-sm);
	}
	.titulo {
		color: var(--text-primary);
	}
	.cuenta {
		color: var(--text-secondary);
		font-variant-numeric: tabular-nums;
	}
	.pista {
		height: 8px;
		border-radius: var(--radius-sm);
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		overflow: hidden;
	}
	.relleno {
		height: 100%;
		background: linear-gradient(90deg, var(--accent-primary), var(--accent-secondary));
		transition: width 0.2s ease-out;
	}
	.relleno.indeterminado {
		width: 30%;
		animation: vaiven 1.2s ease-in-out infinite;
	}
	@keyframes vaiven {
		0% {
			transform: translateX(-100%);
		}
		100% {
			transform: translateX(340%);
		}
	}
	@media (prefers-reduced-motion: reduce) {
		.relleno {
			transition: none;
		}
		.relleno.indeterminado {
			animation: none;
			width: 100%;
			opacity: 0.4;
		}
	}
	.detalle {
		margin: 0;
		font-size: var(--text-xs);
		color: var(--text-muted);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
</style>
