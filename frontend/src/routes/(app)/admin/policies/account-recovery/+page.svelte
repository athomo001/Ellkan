<!-- Autor: Athan Espinoza -->
<script lang="ts">
	import { onMount } from 'svelte';
	import Card from '#lib/components/Card.svelte';
	import Button from '#lib/components/Button.svelte';
	import Table from '#lib/components/Table.svelte';
	import { get } from 'svelte/store';
	import {
		accountRecoveryPolicyApi,
		accountRecoveryAdminApi,
		custodiaRecoveryApi,
		type SolicitudRecoveryAdmin,
		type EstadoCustodia,
		type CustodioPendiente
	} from '#lib/api/admin';
	import { generarClaveOrg, sellarParaCustodio, resellarComoCustodio } from '#lib/crypto/accountRecovery';
	import { huellaDeClave } from '#lib/crypto/emergencia';
	import { clavesDesbloqueadas } from '#lib/state/session';
	import { t } from '#lib/i18n';
	import { ApiError } from '#lib/api/client';

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

	function mensajeDe(err: unknown): string {
		return err instanceof ApiError ? err.message : get(t).admin.comun.error;
	}

	// QA-09: el custodio re-sella en este navegador el escrow para la clave
	// efímera del solicitante — el servidor no puede hacerlo.
	async function reSellar(id: string) {
		const claves = get(clavesDesbloqueadas);
		if (!claves) throw new Error(get(t).admin.politicaRecovery.custodiaClavesBloqueadas);
		const material = await accountRecoveryAdminApi.materialParaCustodio(id);
		const sellado = await resellarComoCustodio(material, claves.x25519Private);
		await accountRecoveryAdminApi.ejecutar(id, sellado);
	}

	let ejecutandoId = $state<string | undefined>();
	async function ejecutar(id: string) {
		ejecutandoId = id;
		errorSolicitudes = undefined;
		try {
			await reSellar(id);
			await cargarSolicitudes();
		} catch (err) {
			errorSolicitudes = err instanceof Error && !(err instanceof ApiError) ? err.message : mensajeDe(err);
		} finally {
			ejecutandoId = undefined;
		}
	}

	async function aprobar(id: string) {
		aprobandoId = id;
		errorSolicitudes = undefined;
		try {
			const r = await accountRecoveryAdminApi.aprobar(id);
			// Si esta aprobación completó el umbral y este admin es custodio,
			// re-sella acá mismo; si no, queda para otro custodio.
			if (r.status === 'awaiting_custodian' && custodia?.my_envelope_b64 && get(clavesDesbloqueadas)) {
				await reSellar(id).catch(() => undefined);
			}
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

	// QA-09: custodia de la clave organizacional.
	let custodia = $state<EstadoCustodia | undefined>();
	let huellaVigente = $state('');
	let huellas = $state<Record<string, string>>({});
	let errorCustodia = $state<string | undefined>();
	let avisoCustodia = $state<string | undefined>();
	let operandoCustodia = $state<string | undefined>();

	async function cargarCustodia() {
		try {
			const c = await custodiaRecoveryApi.estado();
			const mapa: Record<string, string> = {};
			for (const a of [...c.org_admins, ...c.pending_custodians]) mapa[a.user_id] = await huellaDeClave(a.public_key_x25519_b64);
			huellas = mapa;
			huellaVigente = c.current ? await huellaDeClave(c.current.public_key_x25519_b64) : '';
			custodia = c;
		} catch (err) {
			errorCustodia = mensajeDe(err);
		}
	}
	onMount(cargarCustodia);

	async function operarCustodia(clave: string, accion: () => Promise<string | void>) {
		errorCustodia = undefined;
		avisoCustodia = undefined;
		if (!get(clavesDesbloqueadas)) {
			errorCustodia = get(t).admin.politicaRecovery.custodiaClavesBloqueadas;
			return;
		}
		operandoCustodia = clave;
		try {
			avisoCustodia = (await accion()) || undefined;
			await cargarCustodia();
		} catch (err) {
			errorCustodia = mensajeDe(err);
		} finally {
			operandoCustodia = undefined;
		}
	}

	function generarClave(rotar: boolean) {
		if (rotar && !confirm(get(t).admin.politicaRecovery.custodiaConfirmarRotar)) return;
		return operarCustodia('generar', async () => {
			const { publicaB64, sobres } = await generarClaveOrg(custodia?.org_admins ?? []);
			await custodiaRecoveryApi.crearClave(publicaB64, sobres);
		});
	}

	function sellarPara(c: CustodioPendiente) {
		return operarCustodia(c.user_id, async () => {
			const claves = get(clavesDesbloqueadas);
			if (!claves || !custodia?.current || !custodia.my_envelope_b64) return;
			const sellado = await sellarParaCustodio(custodia.my_envelope_b64, claves.x25519Private, c.public_key_x25519_b64);
			await custodiaRecoveryApi.agregarCustodio(custodia.current.id, { admin_id: c.user_id, sealed_private_key_b64: sellado });
		});
	}

	function purgar() {
		if (!confirm(get(t).admin.politicaRecovery.custodiaConfirmarPurgar)) return;
		return operarCustodia('purgar', async () => {
			const r = await custodiaRecoveryApi.purgarClaveServidor();
			return get(t).admin.politicaRecovery.custodiaPurgada.replace('{n}', String(r.escrows_deleted));
		});
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
	<h2>{$t.admin.politicaRecovery.custodiaTitulo}</h2>
	{#if errorCustodia}<p class="error">{errorCustodia}</p>{/if}
	{#if avisoCustodia}<p class="ok">{avisoCustodia}</p>{/if}
	{#if !custodia}
		<!-- Con error de carga no queda un "Cargando…" que nunca termina (#66). -->
		{#if !errorCustodia}<p>{$t.admin.comun.cargando}</p>{/if}
	{:else if !custodia.current || custodia.current.custody === 'server'}
		<p class="secundario">
			{custodia.current ? $t.admin.politicaRecovery.custodiaServidor : $t.admin.politicaRecovery.custodiaNinguna}
		</p>
		<p class="secundario">{$t.admin.politicaRecovery.custodiaSeSellaPara}</p>
		<ul>
			{#each custodia.org_admins as a (a.user_id)}
				<li>{a.display_name} &lt;{a.email}&gt; — <code>{huellas[a.user_id]}</code></li>
			{/each}
		</ul>
		<Button variant="primary" onclick={() => generarClave(false)} loading={operandoCustodia === 'generar'}>
			{$t.admin.politicaRecovery.custodiaGenerar}
		</Button>
	{:else}
		<p class="secundario">{$t.admin.politicaRecovery.custodiaCliente}</p>
		<p class="secundario">{$t.admin.politicaRecovery.custodiaHuella.replace('{huella}', huellaVigente)}</p>
		{#if !custodia.my_envelope_b64}
			<p class="error">{$t.admin.politicaRecovery.custodiaSinCopia}</p>
		{/if}
		{#if custodia.pending_custodians.length > 0}
			<p class="secundario">{$t.admin.politicaRecovery.custodiaPendientes}</p>
			<ul>
				{#each custodia.pending_custodians as c (c.user_id)}
					<li>
						{c.display_name} &lt;{c.email}&gt; — <code>{huellas[c.user_id]}</code>
						{#if custodia.my_envelope_b64}
							<Button variant="secondary" onclick={() => sellarPara(c)} loading={operandoCustodia === c.user_id}>
								{$t.admin.politicaRecovery.custodiaSellarPara.replace('{nombre}', c.display_name)}
							</Button>
						{/if}
					</li>
				{/each}
			</ul>
		{/if}
		{#if custodia.escrows_on_server_key > 0}
			<p class="secundario">
				{$t.admin.politicaRecovery.custodiaEscrowsServidor.replace('{n}', String(custodia.escrows_on_server_key))}
			</p>
			<Button variant="danger" onclick={purgar} loading={operandoCustodia === 'purgar'}>
				{$t.admin.politicaRecovery.custodiaPurgar}
			</Button>
		{/if}
		<Button variant="ghost" onclick={() => generarClave(true)} loading={operandoCustodia === 'generar'}>
			{$t.admin.politicaRecovery.custodiaRotar}
		</Button>
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
			<td>{s.status === 'awaiting_custodian' ? $t.admin.politicaRecovery.estadoEsperaCustodio : s.status}</td>
			<td>{s.approvals_count}/{s.approval_threshold}</td>
			<td class="secundario">{new Date(s.created_at).toLocaleString()}</td>
			<td class="acciones">
				{#if s.status === 'awaiting_custodian'}
					<Button variant="primary" onclick={() => ejecutar(s.id)} loading={ejecutandoId === s.id}>
						{$t.admin.politicaRecovery.ejecutar}
					</Button>
				{:else}
					<Button variant="primary" onclick={() => aprobar(s.id)} loading={aprobandoId === s.id}>
						{$t.admin.politicaRecovery.aprobar}
					</Button>
				{/if}
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
