<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-23: reportes operativos — sólo metadata (fechas, estados, conteos),
	// nunca contenido cifrado. `reportId` es un enum cerrado del lado del
	// servidor (un valor inválido da 404) — acá el selector sólo ofrece los
	// cuatro valores reales, nunca un id libre.
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import Table from '$lib/components/Table.svelte';
	import { reportsApi, type ReportId, type ReportItem } from '$lib/api/admin';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let reportId = $state<ReportId>('passwords_expired');
	let dias = $state('90');
	let cargando = $state(false);
	let error = $state<string | undefined>();
	let items = $state<ReportItem[]>([]);
	let cursorSiguiente = $state<string | undefined>();

	const usaDias = $derived(reportId === 'inactive_users' || reportId === 'resources_never_rotated');

	const columnas = $derived.by(() => {
		if (reportId === 'resources_never_rotated') {
			return [
				{ key: 'recurso', header: $t.admin.reportes.colRecurso },
				{ key: 'creado', header: $t.admin.reportes.colCreado }
			];
		}
		const segunda =
			reportId === 'passwords_expired'
				? $t.admin.reportes.colPassphraseDesde
				: reportId === 'mfa_coverage'
					? $t.admin.reportes.colMfa
					: $t.admin.reportes.colUltimoLogin;
		return [
			{ key: 'email', header: $t.admin.reportes.colEmail },
			{ key: 'segunda', header: segunda }
		];
	});

	async function cargar(desdeCero: boolean) {
		cargando = true;
		error = undefined;
		try {
			const pagina = await reportsApi.obtener(
				reportId,
				desdeCero ? undefined : cursorSiguiente,
				usaDias ? Number(dias) : undefined
			);
			items = desdeCero ? pagina.items : [...items, ...pagina.items];
			cursorSiguiente = pagina.next_cursor ?? undefined;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			cargando = false;
		}
	}

	function alCambiarReporte() {
		items = [];
		cursorSiguiente = undefined;
		error = undefined;
	}
</script>

<h1>{$t.admin.reportes.titulo}</h1>
<Card>
	<div class="controles">
		<div class="field">
			<label for="reportId">{$t.admin.reportes.reporte}</label>
			<select id="reportId" bind:value={reportId} onchange={alCambiarReporte}>
				<option value="passwords_expired">{$t.admin.reportes.passwordsExpired}</option>
				<option value="mfa_coverage">{$t.admin.reportes.mfaCoverage}</option>
				<option value="inactive_users">{$t.admin.reportes.inactiveUsers}</option>
				<option value="resources_never_rotated">{$t.admin.reportes.resourcesNeverRotated}</option>
			</select>
		</div>
		{#if usaDias}
			<TextField label={$t.admin.reportes.umbralDias} type="number" bind:value={dias} />
		{/if}
		<Button variant="primary" onclick={() => cargar(true)} loading={cargando}>{$t.admin.comun.buscar}</Button>
	</div>

	{#if reportId === 'passwords_expired'}
		<p class="hint">{$t.admin.reportes.hintPasswordsExpired}</p>
	{/if}

	{#if error}<p class="error">{error}</p>{/if}

	{#if items.length > 0 || !cargando}
		<Table {columnas} filas={items} claveFila={(f) => f.user_id ?? f.resource_id ?? ''} vacio={$t.admin.reportes.sinResultados}>
			{#snippet fila(f)}
				{#if reportId === 'resources_never_rotated'}
					<td><code>{f.resource_id}</code></td>
					<td>{f.created_at}</td>
				{:else}
					<td>{f.email}</td>
					{#if reportId === 'passwords_expired'}
						<td>{f.passphrase_set_at}</td>
					{:else if reportId === 'mfa_coverage'}
						<td>{f.mfa_enabled ? $t.admin.comun.si : $t.admin.comun.no}</td>
					{:else if reportId === 'inactive_users'}
						<td>{f.last_login_at ?? $t.admin.reportes.nunca}</td>
					{/if}
				{/if}
			{/snippet}
		</Table>
		{#if items.length > 0 && cursorSiguiente}
			<Button variant="secondary" onclick={() => cargar(false)} loading={cargando}>{$t.admin.auditoria.cargarMas}</Button>
		{/if}
	{/if}
</Card>

<style>
	h1 {
		margin: 0 0 var(--space-6) 0;
		font-size: var(--text-2xl);
		color: var(--text-primary);
	}
	.controles {
		display: flex;
		align-items: flex-end;
		gap: var(--space-3);
		flex-wrap: wrap;
		margin-bottom: var(--space-4);
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	label {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		font-weight: 500;
	}
	select {
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
		color: var(--text-primary);
	}
	.hint {
		color: var(--text-muted);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-4) 0;
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
	}
</style>
