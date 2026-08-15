<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-20: landing real del panel — antes redirigía directo a `/admin/users`
	// sin dar ninguna orientación. Grid de accesos directos agrupado por
	// categoría (misma fuente que el nav de `(app)/admin/+layout.svelte`,
	// `secciones.ts`) — las métricas reales ya viven en `/admin/reports` y
	// `/admin/system-status`, no hace falta duplicarlas acá con una llamada
	// aparte.
	import Card from '$lib/components/Card.svelte';
	import { t } from '$lib/i18n';
	import { categorias } from './secciones';
</script>

<h1>{$t.admin.landing.titulo}</h1>
<p class="hint">{$t.admin.landing.hint}</p>

{#each categorias as categoria (categoria.titulo($t))}
	<h2>{categoria.titulo($t)}</h2>
	<div class="grid">
		{#each categoria.items as seccion (seccion.href)}
			<a href={seccion.href} class="tarjeta">
				<Card>{seccion.label($t)}</Card>
			</a>
		{/each}
	</div>
{/each}

<style>
	h1 {
		margin: 0 0 var(--space-2) 0;
		font-size: var(--text-2xl);
		color: var(--text-primary);
	}
	.hint {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-6) 0;
	}
	h2 {
		margin: 0 0 var(--space-2) 0;
		font-size: var(--text-sm);
		font-weight: 600;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		color: var(--text-muted);
	}
	.grid {
		display: grid;
		grid-template-columns: repeat(auto-fill, minmax(12rem, 1fr));
		gap: var(--space-3);
		margin-bottom: var(--space-6);
	}
	.tarjeta {
		color: var(--text-primary);
		text-decoration: none;
		font-size: var(--text-sm);
		font-weight: 500;
	}
	.tarjeta:hover {
		color: var(--accent-primary);
	}
</style>
