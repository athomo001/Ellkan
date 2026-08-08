<!-- Autor: Athan Espinoza -->
<script lang="ts">
	import TextField from './TextField.svelte';
	import Button from './Button.svelte';
	import { t } from '$lib/i18n';
	import { descendientesDe, type NodoCarpeta } from '$lib/crypto/carpetas';

	let {
		nodos,
		cargando = false,
		onCrear,
		onMover
	}: {
		nodos: NodoCarpeta[];
		cargando?: boolean;
		onCrear?: (nombre: string, parentId: string | null) => void | Promise<void>;
		onMover?: (folderId: string, newParentId: string | null) => void | Promise<void>;
	} = $props();

	// F-09: sin endpoint para asignar recursos a una carpeta todavía
	// (`backend/src/folders/mod.rs`, gap real documentado) — este árbol es
	// puramente organizativo por ahora, no filtra el listado de recursos.
	let creandoEn = $state<string | null | undefined>(undefined);
	let nombreNuevo = $state('');
	let creando = $state(false);

	function hijosDe(parentId: string | null): NodoCarpeta[] {
		return nodos.filter((n) => n.parentId === parentId);
	}

	async function confirmarCrear(parentId: string | null) {
		if (!nombreNuevo.trim() || !onCrear) return;
		creando = true;
		try {
			await onCrear(nombreNuevo.trim(), parentId);
			nombreNuevo = '';
			creandoEn = undefined;
		} finally {
			creando = false;
		}
	}

	async function mover(folderId: string, valor: string) {
		if (!onMover) return;
		await onMover(folderId, valor === '' ? null : valor);
	}

	function destinosValidos(folderId: string): NodoCarpeta[] {
		const excluidos = descendientesDe(folderId, nodos);
		excluidos.add(folderId);
		return nodos.filter((n) => !excluidos.has(n.id));
	}
</script>

{#snippet rama(parentId: string | null)}
	<ul class="rama">
		{#each hijosDe(parentId) as nodo (nodo.id)}
			<li>
				<div class="fila">
					<span class="nombre">{nodo.nombre}</span>
					{#if onMover}
						<select
							class="mover"
							value={nodo.parentId ?? ''}
							onchange={(e) => mover(nodo.id, e.currentTarget.value)}
							title={$t.vault.carpetas.mover}
						>
							<option value="">{$t.vault.carpetas.raiz}</option>
							{#each destinosValidos(nodo.id) as destino (destino.id)}
								<option value={destino.id}>{destino.nombre}</option>
							{/each}
						</select>
					{/if}
					{#if onCrear}
						<button
							type="button"
							class="agregar"
							onclick={() => (creandoEn = creandoEn === nodo.id ? undefined : nodo.id)}
						>
							+
						</button>
					{/if}
				</div>
				{#if creandoEn === nodo.id}
					<div class="form-nueva">
						<TextField label={$t.vault.carpetas.nombreCarpeta} bind:value={nombreNuevo} />
						<Button variant="secondary" loading={creando} onclick={() => confirmarCrear(nodo.id)}>
							{$t.vault.carpetas.crear}
						</Button>
					</div>
				{/if}
				{@render rama(nodo.id)}
			</li>
		{/each}
	</ul>
{/snippet}

<div class="folder-tree">
	<div class="cabecera">
		<h2>{$t.vault.carpetas.titulo}</h2>
		{#if onCrear}
			<button type="button" class="agregar" onclick={() => (creandoEn = creandoEn === null ? undefined : null)}>
				+
			</button>
		{/if}
	</div>
	{#if creandoEn === null}
		<div class="form-nueva">
			<TextField label={$t.vault.carpetas.nombreCarpeta} bind:value={nombreNuevo} />
			<Button variant="secondary" loading={creando} onclick={() => confirmarCrear(null)}>
				{$t.vault.carpetas.crear}
			</Button>
		</div>
	{/if}
	{#if cargando}
		<p class="hint">{$t.vault.carpetas.cargando}</p>
	{:else if nodos.length === 0}
		<p class="hint">{$t.vault.carpetas.sinCarpetas}</p>
	{:else}
		{@render rama(null)}
	{/if}
	<p class="hint hint-limite">{$t.vault.carpetas.hintSinAsociarRecursos}</p>
</div>

<style>
	.folder-tree {
		font-size: var(--text-sm);
	}
	.cabecera {
		display: flex;
		align-items: center;
		justify-content: space-between;
		margin-bottom: var(--space-3);
	}
	h2 {
		margin: 0;
		font-size: var(--text-sm);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		color: var(--text-muted);
	}
	.rama {
		list-style: none;
		margin: 0;
		padding-left: var(--space-4);
	}
	.rama:first-of-type {
		padding-left: 0;
	}
	.fila {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding: var(--space-1) 0;
	}
	.nombre {
		flex: 1;
		color: var(--text-primary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.mover {
		max-width: 8rem;
		font-size: var(--text-xs);
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
	}
	.agregar {
		background: none;
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		width: 1.5rem;
		height: 1.5rem;
		line-height: 1;
		color: var(--text-secondary);
		cursor: pointer;
		flex-shrink: 0;
	}
	.agregar:hover {
		background: var(--bg-overlay);
		color: var(--text-primary);
	}
	.form-nueva {
		display: flex;
		align-items: flex-end;
		gap: var(--space-2);
		margin: var(--space-2) 0;
	}
	.hint {
		color: var(--text-muted);
		font-size: var(--text-xs);
	}
	.hint-limite {
		margin-top: var(--space-3);
		padding-top: var(--space-3);
		border-top: 1px solid var(--border-color);
	}
</style>
