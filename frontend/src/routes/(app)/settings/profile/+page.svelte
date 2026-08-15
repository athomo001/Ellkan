<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-01: "Perfil" — sección de sólo lectura de "Mi cuenta"
	// ((app)/settings/+layout.svelte). Antes vivía junto a otras 4
	// secciones en una sola página larga; separado en su propia ruta para
	// no obligar a hacer scroll para llegar a algo puntual.
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import { perfilApi, misGruposApi, type Perfil, type GrupoDeUsuario } from '$lib/api/profile';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let cargando = $state(true);
	let perfil = $state<Perfil | undefined>();
	let grupos = $state<GrupoDeUsuario[]>([]);
	let error = $state<string | undefined>();

	onMount(async () => {
		try {
			[perfil, grupos] = await Promise.all([perfilApi.obtener(), misGruposApi.listar()]);
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.settingsProfile.error;
		} finally {
			cargando = false;
		}
	});
</script>

<svelte:head>
	<title>{$t.settingsProfile.perfilTitulo} — Ellkan</title>
</svelte:head>

<h1>{$t.settingsProfile.perfilTitulo}</h1>
<Card>
	{#if cargando}
		<p class="hint">{$t.settingsProfile.cargando}</p>
	{:else if error}
		<p class="error">{error}</p>
	{:else if perfil}
		<dl>
			<dt>{$t.settingsProfile.nombre}</dt>
			<dd>{perfil.display_name}</dd>
			<dt>{$t.settingsProfile.email}</dt>
			<dd>{perfil.email}</dd>
			<dt>{$t.settingsProfile.rol}</dt>
			<dd>{perfil.role}</dd>
			<dt>{$t.settingsProfile.creado}</dt>
			<dd>{new Date(perfil.created_at).toLocaleString()}</dd>
			<dt>{$t.settingsProfile.modificado}</dt>
			<dd>{new Date(perfil.updated_at).toLocaleString()}</dd>
		</dl>
	{/if}
</Card>

{#if !cargando && !error}
	<Card>
		<h2>{$t.settingsProfile.gruposTitulo}</h2>
		{#if grupos.length === 0}
			<p class="hint">{$t.settingsProfile.sinGrupos}</p>
		{:else}
			<ul class="grupos">
				{#each grupos as g (g.group_id)}
					<li>
						{g.name}
						{#if g.is_admin}<span class="badge">{$t.settingsProfile.adminDeGrupo}</span>{/if}
					</li>
				{/each}
			</ul>
		{/if}
	</Card>
{/if}

<style>
	h1 {
		margin: 0 0 var(--space-6) 0;
		font-size: var(--text-2xl);
		color: var(--text-primary);
	}
	.hint {
		color: var(--text-secondary);
		font-size: var(--text-sm);
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
	}
	dl {
		display: grid;
		grid-template-columns: auto 1fr;
		gap: var(--space-1) var(--space-4);
		margin: 0;
	}
	dt {
		color: var(--text-secondary);
		font-size: var(--text-sm);
	}
	dd {
		margin: 0;
		color: var(--text-primary);
		font-size: var(--text-sm);
	}
	h2 {
		margin: 0 0 var(--space-3) 0;
		font-size: var(--text-lg);
		color: var(--text-primary);
	}
	.grupos {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.badge {
		margin-left: var(--space-2);
		font-size: var(--text-xs);
		color: var(--accent-primary);
		background: color-mix(in srgb, var(--accent-primary) 18%, var(--bg-base));
		border-radius: 999px;
		padding: 0.1rem var(--space-2);
	}
</style>
