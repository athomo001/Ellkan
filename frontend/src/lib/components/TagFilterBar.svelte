<!-- Autor: Athan Espinoza -->
<script lang="ts">
	import TextField from './TextField.svelte';
	import Button from './Button.svelte';
	import { t } from '$lib/i18n';
	import type { Tag } from '$lib/api/tags';

	let {
		tags,
		seleccionados = $bindable([]),
		cargando = false,
		onCrear
	}: {
		tags: Tag[];
		seleccionados?: string[];
		cargando?: boolean;
		onCrear?: (name: string, isShared: boolean) => void | Promise<void>;
	} = $props();

	function toggle(id: string) {
		seleccionados = seleccionados.includes(id) ? seleccionados.filter((x) => x !== id) : [...seleccionados, id];
	}

	let creandoTag = $state(false);
	let nombreNuevo = $state('');
	let esCompartido = $state(false);
	let creando = $state(false);

	async function confirmarCrear(e: SubmitEvent) {
		e.preventDefault();
		if (!nombreNuevo.trim() || !onCrear) return;
		creando = true;
		try {
			await onCrear(nombreNuevo.trim(), esCompartido);
			nombreNuevo = '';
			esCompartido = false;
			creandoTag = false;
		} finally {
			creando = false;
		}
	}
</script>

<div class="tag-bar">
	{#if cargando}
		<span class="hint">{$t.vault.tags.cargando}</span>
	{:else}
		<button type="button" class="chip" class:activo={seleccionados.length === 0} onclick={() => (seleccionados = [])}>
			{$t.vault.tags.todos}
		</button>
		{#each tags as tag (tag.id)}
			<button
				type="button"
				class="chip"
				class:activo={seleccionados.includes(tag.id)}
				class:compartido={tag.is_shared}
				onclick={() => toggle(tag.id)}
			>
				{tag.name}
			</button>
		{/each}
		{#if onCrear}
			<button type="button" class="chip chip-agregar" onclick={() => (creandoTag = !creandoTag)}>
				+ {$t.vault.tags.nuevoTag}
			</button>
		{/if}
	{/if}
</div>

{#if creandoTag}
	<form class="form-nuevo-tag" onsubmit={confirmarCrear}>
		<TextField label={$t.vault.tags.nombreTag} bind:value={nombreNuevo} />
		<label class="check">
			<input type="checkbox" bind:checked={esCompartido} />
			{$t.vault.tags.compartidoCheckbox}
		</label>
		<Button type="submit" variant="secondary" loading={creando}>{$t.vault.tags.crear}</Button>
	</form>
{/if}

<style>
	.tag-bar {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
		margin-bottom: var(--space-4);
	}
	.chip {
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-left: 3px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-1) var(--space-3);
		font-size: var(--text-xs);
		color: var(--text-secondary);
		cursor: pointer;
	}
	.chip.compartido {
		border-left-color: var(--accent-primary);
	}
	.chip.activo {
		color: var(--text-primary);
		border-color: var(--accent-primary);
	}
	.chip-agregar {
		border-style: dashed;
	}
	.hint {
		color: var(--text-muted);
		font-size: var(--text-xs);
	}
	.form-nuevo-tag {
		display: flex;
		align-items: flex-end;
		gap: var(--space-3);
		flex-wrap: wrap;
		margin-bottom: var(--space-4);
	}
	.check {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		padding-bottom: var(--space-2);
	}
</style>
