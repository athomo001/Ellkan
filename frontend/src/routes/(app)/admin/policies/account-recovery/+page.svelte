<!-- Autor: Athan Espinoza -->
<script lang="ts">
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import Table from '$lib/components/Table.svelte';
	import { accountRecoveryPolicyApi, accountRecoveryAdminApi, type SolicitudRecoveryAdmin } from '$lib/api/admin';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let cargando = $state(true);
	let guardando = $state(false);
	let error = $state<string | undefined>();
	let guardado = $state(false);

	let required = $state(false);
	let graceDays = $state('14');
	let threshold = $state('2');

	onMount(async () => {
		try {
			const p = await accountRecoveryPolicyApi.obtener();
			required = p.required;
			graceDays = String(p.grace_period_days);
			threshold = String(p.default_approval_threshold);
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			cargando = false;
		}
	});

	// Solicitudes pendientes — el id de una solicitud sólo lo conoce quien
	// la creó, este listado es la única forma de que un admin se entere de
	// que hay algo para aprobar.
	let solicitudes = $state<SolicitudRecoveryAdmin[]>([]);
	let cargandoSolicitudes = $state(true);
	let aprobandoId = $state<string | undefined>();
	let rechazandoId = $state<string | undefined>();
	let errorSolicitudes = $state<string | undefined>();

	async function cargarSolicitudes() {
		cargandoSolicitudes = true;
		try {
			solicitudes = await accountRecoveryAdminApi.listarPendientes();
		} catch (err) {
			errorSolicitudes = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			cargandoSolicitudes = false;
		}
	}
	onMount(cargarSolicitudes);

	async function aprobar(id: string) {
		aprobandoId = id;
		errorSolicitudes = undefined;
		try {
			await accountRecoveryAdminApi.aprobar(id);
			await cargarSolicitudes();
		} catch (err) {
			errorSolicitudes = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			aprobandoId = undefined;
		}
	}

	// 2026-08-11: delegado a admin de grupo, mismo criterio que aprobar — el
	// backend ya filtra qué solicitudes ve y puede resolver este admin.
	async function rechazar(id: string) {
		rechazandoId = id;
		errorSolicitudes = undefined;
		try {
			await accountRecoveryAdminApi.rechazar(id);
			await cargarSolicitudes();
		} catch (err) {
			errorSolicitudes = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			rechazandoId = undefined;
		}
	}

	async function guardar(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;
		guardado = false;
		guardando = true;
		try {
			await accountRecoveryPolicyApi.actualizar({
				required,
				grace_period_days: Number(graceDays),
				default_approval_threshold: Number(threshold)
			});
			guardado = true;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			guardando = false;
		}
	}
</script>

<h1>{$t.admin.politicaRecovery.titulo}</h1>
<Card>
	{#if cargando}
		<p>{$t.admin.comun.cargando}</p>
	{:else}
		<form onsubmit={guardar}>
			<label class="check"><input type="checkbox" bind:checked={required} /> {$t.admin.politicaRecovery.requerido}</label>
			<div class="field">
				<label for="grace">{$t.admin.politicaRecovery.diasGracia}</label>
				<input id="grace" type="number" min="0" bind:value={graceDays} />
			</div>
			<div class="field">
				<label for="threshold">{$t.admin.politicaRecovery.umbralAprobacion}</label>
				<input id="threshold" type="number" min="1" bind:value={threshold} />
			</div>
			{#if error}<p class="error">{error}</p>{/if}
			{#if guardado}<p class="ok">{$t.admin.comun.guardado}</p>{/if}
			<Button type="submit" variant="primary" loading={guardando}>{$t.admin.comun.guardar}</Button>
		</form>
	{/if}
</Card>

<Card>
	<h2>{$t.admin.politicaRecovery.solicitudesTitulo}</h2>
	{#if errorSolicitudes}<p class="error">{errorSolicitudes}</p>{/if}
	<Table
		columnas={[
			{ key: 'email', header: $t.admin.politicaRecovery.colEmail },
			{ key: 'estado', header: $t.admin.politicaRecovery.colEstado },
			{ key: 'aprobaciones', header: $t.admin.politicaRecovery.colAprobaciones },
			{ key: 'fecha', header: $t.admin.politicaRecovery.colFecha },
			{ key: 'acciones', header: '' }
		]}
		filas={solicitudes}
		claveFila={(f) => f.id}
		cargando={cargandoSolicitudes}
		textoCargando={$t.admin.comun.cargando}
		vacio={$t.admin.politicaRecovery.sinSolicitudes}
	>
		{#snippet fila(s)}
			<td>{s.target_email}</td>
			<td>{s.status}</td>
			<td>{s.approvals_count}/{s.approval_threshold}</td>
			<td class="secundario">{new Date(s.created_at).toLocaleString()}</td>
			<td class="acciones">
				<Button variant="primary" onclick={() => aprobar(s.id)} loading={aprobandoId === s.id}>
					{$t.admin.politicaRecovery.aprobar}
				</Button>
				<Button variant="danger" onclick={() => rechazar(s.id)} loading={rechazandoId === s.id}>
					{$t.admin.politicaRecovery.rechazar}
				</Button>
			</td>
		{/snippet}
	</Table>
</Card>

<style>
	h1 {
		margin: 0 0 var(--space-6) 0;
		font-size: var(--text-2xl);
		color: var(--text-primary);
	}
	h2 {
		margin: 0 0 var(--space-4) 0;
		font-size: var(--text-lg);
		color: var(--text-primary);
	}
	.secundario {
		color: var(--text-secondary);
	}
	.acciones {
		display: flex;
		gap: var(--space-2);
	}
	:global(.card) + :global(.card) {
		margin-top: var(--space-4);
	}
	form {
		display: flex;
		flex-direction: column;
		max-width: 28rem;
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		margin-bottom: var(--space-4);
	}
	label {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		font-weight: 500;
	}
	.check {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		margin-bottom: var(--space-4);
	}
	input {
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
		color: var(--text-primary);
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
	}
	.ok {
		color: var(--success);
		font-size: var(--text-sm);
	}
</style>
