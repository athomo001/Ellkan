<!-- Autor: Athan Espinoza -->
<script lang="ts">
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import Table from '$lib/components/Table.svelte';
	import { auditLogApi, type AuditLogEntry, type AuditLogFiltro } from '$lib/api/admin';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let cargando = $state(true);
	let error = $state<string | undefined>();
	let items = $state<AuditLogEntry[]>([]);
	let nextCursor = $state<string | null>(null);

	let actorUserId = $state('');
	let eventType = $state('');
	let desde = $state('');
	let hasta = $state('');

	function filtroActual(): AuditLogFiltro {
		return {
			actor_user_id: actorUserId || undefined,
			event_type: eventType || undefined,
			from: desde ? new Date(desde).toISOString() : undefined,
			to: hasta ? new Date(hasta).toISOString() : undefined
		};
	}

	async function filtrar(e?: SubmitEvent) {
		e?.preventDefault();
		cargando = true;
		error = undefined;
		try {
			const pagina = await auditLogApi.listar(filtroActual());
			items = pagina.items;
			nextCursor = pagina.next_cursor;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			cargando = false;
		}
	}
	onMount(() => filtrar());

	let cargandoMas = $state(false);
	async function cargarMas() {
		if (!nextCursor) return;
		cargandoMas = true;
		try {
			const pagina = await auditLogApi.listar({ ...filtroActual(), cursor: nextCursor });
			items = [...items, ...pagina.items];
			nextCursor = pagina.next_cursor;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			cargandoMas = false;
		}
	}
</script>

<h1>{$t.admin.auditoria.titulo}</h1>
<Card>
	<form onsubmit={filtrar} class="filtros">
		<TextField label={$t.admin.auditoria.actorUserId} bind:value={actorUserId} />
		<TextField label={$t.admin.auditoria.tipoEvento} bind:value={eventType} />
		<TextField label={$t.admin.auditoria.desde} type="text" bind:value={desde} hint="YYYY-MM-DD" />
		<TextField label={$t.admin.auditoria.hasta} type="text" bind:value={hasta} hint="YYYY-MM-DD" />
		<Button type="submit" variant="primary" loading={cargando}>{$t.admin.auditoria.filtrar}</Button>
	</form>

	<div class="export">
		<button type="button" class="link" onclick={() => auditLogApi.descargarExport(filtroActual(), 'ndjson')}
			>{$t.admin.auditoria.exportarNdjson}</button
		>
		<button type="button" class="link" onclick={() => auditLogApi.descargarExport(filtroActual(), 'csv')}
			>{$t.admin.auditoria.exportarCsv}</button
		>
	</div>

	{#if error}<p class="error">{error}</p>{/if}

	{#if !cargando}
		<Table
			columnas={[
				{ key: 'actor', header: $t.admin.auditoria.actorUserId },
				{ key: 'evento', header: $t.admin.auditoria.tipoEvento },
				{ key: 'fecha', header: $t.admin.auditoria.fecha }
			]}
			filas={items}
			claveFila={(f) => f.id}
			vacio={$t.admin.auditoria.sinResultados}
		>
			{#snippet fila(it)}
				<td>{it.actor_user_id ?? '—'}</td>
				<td>{it.event_type}</td>
				<td>{it.created_at}</td>
			{/snippet}
		</Table>
		{#if items.length > 0 && nextCursor}
			<Button variant="secondary" onclick={cargarMas} loading={cargandoMas}>{$t.admin.auditoria.cargarMas}</Button>
		{/if}
	{/if}
</Card>

<style>
	h1 {
		margin: 0 0 var(--space-6) 0;
		font-size: var(--text-2xl);
		color: var(--text-primary);
	}
	.filtros {
		display: flex;
		flex-wrap: wrap;
		align-items: flex-end;
		gap: var(--space-3);
		margin-bottom: var(--space-3);
	}
	.export {
		display: flex;
		gap: var(--space-3);
		margin-bottom: var(--space-4);
	}
	.export .link {
		background: none;
		border: none;
		padding: 0;
		font-size: var(--text-sm);
		color: var(--accent-primary);
		cursor: pointer;
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
	}
</style>
