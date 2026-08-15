<!-- Autor: Athan Espinoza -->
<script lang="ts" generics="T">
	// F-20/01-propuesta-tecnica.md §3.5: tabla densa y plana (sin
	// gradiente/glow, reservados a acentos de marca) — reemplaza los `<ul>`
	// sin estilo de las páginas de admin. El panel de detalle (edición,
	// purge dry-run, miembros de grupo) sigue viviendo en cada página, no
	// acá adentro: las cinco páginas que la adoptan tienen detalles
	// completamente distintos entre sí.
	import type { Snippet } from 'svelte';

	let {
		columnas,
		filas,
		claveFila,
		cargando = false,
		textoCargando,
		vacio,
		seleccionadaId,
		onSeleccionar,
		fila
	}: {
		columnas: { key: string; header: string }[];
		filas: T[];
		claveFila: (f: T) => string;
		cargando?: boolean;
		textoCargando?: string;
		vacio?: string;
		seleccionadaId?: string;
		onSeleccionar?: (f: T) => void;
		fila: Snippet<[T]>;
	} = $props();
</script>

<div class="tabla-scroll">
	<table>
		<thead>
			<tr>
				{#each columnas as col (col.key)}
					<th>{col.header}</th>
				{/each}
			</tr>
		</thead>
		<tbody>
			{#if cargando}
				<tr class="sin-filas"><td colspan={columnas.length}>{textoCargando}</td></tr>
			{:else if filas.length === 0}
				<tr class="sin-filas"><td colspan={columnas.length}>{vacio}</td></tr>
			{:else}
				{#each filas as f (claveFila(f))}
					{#if onSeleccionar}
						<tr
							class="clickeable"
							class:seleccionada={claveFila(f) === seleccionadaId}
							onclick={() => onSeleccionar(f)}
						>
							{@render fila(f)}
						</tr>
					{:else}
						<tr>
							{@render fila(f)}
						</tr>
					{/if}
				{/each}
			{/if}
		</tbody>
	</table>
</div>

<style>
	.tabla-scroll {
		overflow-x: auto;
	}
	table {
		width: 100%;
		border-collapse: collapse;
		font-size: var(--text-sm);
	}
	th {
		text-align: left;
		font-weight: 500;
		color: var(--text-muted);
		font-size: var(--text-xs);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		padding: var(--space-2) var(--space-3);
		border-bottom: 1px solid var(--border-color);
		white-space: nowrap;
	}
	tbody :global(td) {
		padding: var(--space-2) var(--space-3);
		border-bottom: 1px solid var(--border-color);
		color: var(--text-primary);
	}
	tr.clickeable {
		cursor: pointer;
	}
	tr.clickeable:hover {
		background: var(--bg-overlay);
	}
	tr.seleccionada {
		background: var(--bg-overlay);
		box-shadow: inset 2px 0 0 var(--accent-primary);
	}
	.sin-filas td {
		color: var(--text-muted);
		padding: var(--space-3);
	}
</style>
