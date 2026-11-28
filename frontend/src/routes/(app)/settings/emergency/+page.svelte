<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-36 (pendiente #131): acceso de emergencia. Arriba, las personas que
	// yo designé (aprobar/rechazar una solicitud, revocar); en el medio, el
	// alta de un contacto, que sella mis claves privadas para su clave
	// pública después de mostrar la huella para compararla; abajo, las
	// cuentas de las que yo soy contacto (aceptar, pedir acceso).
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { get } from 'svelte/store';
	import Card from '#lib/components/Card.svelte';
	import Button from '#lib/components/Button.svelte';
	import TextField from '#lib/components/TextField.svelte';
	import { emergenciaApi, type AccesoEmergencia, type NivelEmergencia, type PersonaEmergencia } from '#lib/api/emergencia';
	import { buscarContacto, sellarMaterialParaContacto, type ContactoConClave } from '#lib/crypto/emergencia';
	import { sesion, clavesDesbloqueadas } from '#lib/state/session';
	import { ApiError } from '#lib/api/client';
	import { t } from '#lib/i18n';

	let accesos = $state<AccesoEmergencia[]>([]);
	let cargando = $state(true);
	let error = $state<string | undefined>();
	let ocupadoId = $state<string | null>(null);

	const yo = $derived($sesion.userId);
	const misContactos = $derived(accesos.filter((a) => a.granter_id === yo));
	const soyContactoDe = $derived(accesos.filter((a) => a.grantee_id === yo));

	function mensaje(err: unknown): string {
		return err instanceof ApiError ? err.message : get(t).settingsEmergency.error;
	}

	function nombre(p: PersonaEmergencia): string {
		return p.display_name ? `${p.display_name} (${p.email})` : p.email;
	}

	function textoNivel(nivel: NivelEmergencia): string {
		return nivel === 'takeover' ? $t.settingsEmergency.nivelTakeover : $t.settingsEmergency.nivelView;
	}

	function textoEstado(a: AccesoEmergencia): string {
		const e = $t.settingsEmergency;
		if (a.status === 'invited') return e.estadoInvitado;
		switch (a.request_status) {
			case 'pending':
				return e.estadoPendiente;
			case 'approved':
			case 'granted_by_timeout':
				return e.estadoConcedido;
			case 'rejected':
				return e.estadoRechazado;
			default:
				return e.estadoActivo;
		}
	}

	async function cargar() {
		cargando = true;
		error = undefined;
		try {
			accesos = await emergenciaApi.listar();
		} catch (err) {
			error = mensaje(err);
		} finally {
			cargando = false;
		}
	}

	onMount(cargar);

	async function accion(id: string, hacer: (id: string) => Promise<void>) {
		ocupadoId = id;
		error = undefined;
		try {
			await hacer(id);
			await cargar();
		} catch (err) {
			error = mensaje(err);
		} finally {
			ocupadoId = null;
		}
	}

	// Alta de un contacto: buscar → comparar huella → confirmar.
	let email = $state('');
	let nivel = $state<NivelEmergencia>('view');
	let dias = $state('7');
	let contacto = $state<ContactoConClave | null>(null);
	let huellaConfirmada = $state(false);
	let buscando = $state(false);
	let designando = $state(false);
	let errorAlta = $state<string | undefined>();

	async function buscar(e: SubmitEvent) {
		e.preventDefault();
		errorAlta = undefined;
		contacto = null;
		huellaConfirmada = false;
		buscando = true;
		try {
			contacto = await buscarContacto(email);
		} catch (err) {
			errorAlta = mensaje(err);
		} finally {
			buscando = false;
		}
	}

	async function designar() {
		const claves = get(clavesDesbloqueadas);
		if (!contacto || !claves) return;
		const plazo = Number(dias);
		if (!Number.isInteger(plazo) || plazo < 1 || plazo > 90) {
			errorAlta = $t.settingsEmergency.diasInvalidos;
			return;
		}
		designando = true;
		errorAlta = undefined;
		try {
			await emergenciaApi.designar({
				grantee_id: contacto.user_id,
				access_level: nivel,
				sealed_material_b64: await sellarMaterialParaContacto(contacto, claves),
				wait_time_days: plazo
			});
			email = '';
			contacto = null;
			huellaConfirmada = false;
			await cargar();
		} catch (err) {
			errorAlta = mensaje(err);
		} finally {
			designando = false;
		}
	}
</script>

<svelte:head>
	<title>{$t.settingsEmergency.titulo} — Ellkan</title>
</svelte:head>

<h1>{$t.settingsEmergency.titulo}</h1>
<p class="hint">{$t.settingsEmergency.intro}</p>

{#if error}
	<p class="error" role="alert">{error}</p>
{/if}

<Card>
	<h2>{$t.settingsEmergency.misContactosTitulo}</h2>
	{#if cargando}
		<p class="hint">{$t.settingsEmergency.cargando}</p>
	{:else if misContactos.length === 0}
		<p class="hint">{$t.settingsEmergency.sinContactos}</p>
	{:else}
		<ul class="lista">
			{#each misContactos as a (a.id)}
				<li>
					<div class="info">
						<strong>{nombre(a.grantee)}</strong>
						<span class="secundario">
							{textoNivel(a.access_level)} · {$t.settingsEmergency.plazo.replace('{dias}', String(a.wait_time_days))} · {textoEstado(a)}
						</span>
					</div>
					<div class="acciones">
						{#if a.request_status === 'pending'}
							<Button variant="primary" onclick={() => accion(a.id, emergenciaApi.rechazar)} loading={ocupadoId === a.id}>
								{$t.settingsEmergency.rechazar}
							</Button>
							<Button variant="secondary" onclick={() => accion(a.id, emergenciaApi.aprobar)} disabled={ocupadoId === a.id}>
								{$t.settingsEmergency.aprobar}
							</Button>
						{/if}
						<Button variant="danger" onclick={() => accion(a.id, emergenciaApi.revocar)} disabled={ocupadoId === a.id}>
							{$t.settingsEmergency.revocar}
						</Button>
					</div>
				</li>
			{/each}
		</ul>
	{/if}
</Card>

<Card>
	<h2>{$t.settingsEmergency.altaTitulo}</h2>
	<p class="hint">{$t.settingsEmergency.altaHint}</p>
	<form onsubmit={buscar}>
		<TextField label={$t.settingsEmergency.emailContacto} type="email" bind:value={email} required autocomplete="off" />
		<label class="campo">
			{$t.settingsEmergency.nivel}
			<select bind:value={nivel}>
				<option value="view">{$t.settingsEmergency.nivelView}</option>
				<option value="takeover">{$t.settingsEmergency.nivelTakeover}</option>
			</select>
		</label>
		<TextField label={$t.settingsEmergency.dias} type="number" bind:value={dias} hint={$t.settingsEmergency.diasHint} required />
		<Button type="submit" variant="secondary" loading={buscando}>{$t.settingsEmergency.buscar}</Button>
	</form>

	{#if contacto}
		<div class="huella">
			<p>{$t.settingsEmergency.huellaIntro}</p>
			<p class="mono">{contacto.huella}</p>
			<label class="confirmar">
				<input type="checkbox" bind:checked={huellaConfirmada} />
				{$t.settingsEmergency.huellaConfirmo}
			</label>
			<Button variant="primary" onclick={designar} loading={designando} disabled={!huellaConfirmada || !$clavesDesbloqueadas}>
				{$t.settingsEmergency.designar}
			</Button>
		</div>
	{/if}
	{#if errorAlta}
		<p class="error" role="alert">{errorAlta}</p>
	{/if}
</Card>

<Card>
	<h2>{$t.settingsEmergency.soyContactoTitulo}</h2>
	{#if cargando}
		<p class="hint">{$t.settingsEmergency.cargando}</p>
	{:else if soyContactoDe.length === 0}
		<p class="hint">{$t.settingsEmergency.sinTitulares}</p>
	{:else}
		<ul class="lista">
			{#each soyContactoDe as a (a.id)}
				<li>
					<div class="info">
						<strong>{nombre(a.granter)}</strong>
						<span class="secundario">
							{textoNivel(a.access_level)} · {$t.settingsEmergency.plazo.replace('{dias}', String(a.wait_time_days))} · {textoEstado(a)}
						</span>
						{#if a.sealed_material_b64}
							<span class="secundario">{$t.settingsEmergency.concedidoNota}</span>
						{/if}
					</div>
					<div class="acciones">
						{#if a.status === 'invited'}
							<Button variant="primary" onclick={() => accion(a.id, emergenciaApi.aceptar)} loading={ocupadoId === a.id}>
								{$t.settingsEmergency.aceptar}
							</Button>
						{:else if a.sealed_material_b64}
							<Button variant="primary" onclick={() => goto(`/settings/emergency/${a.id}`)}>
								{$t.settingsEmergency.verBoveda}
							</Button>
						{:else if a.request_status !== 'pending' && !a.sealed_material_b64}
							<Button variant="secondary" onclick={() => accion(a.id, emergenciaApi.solicitar)} loading={ocupadoId === a.id}>
								{$t.settingsEmergency.solicitar}
							</Button>
						{/if}
					</div>
				</li>
			{/each}
		</ul>
	{/if}
</Card>

<style>
	h1 {
		margin: 0 0 var(--space-2) 0;
		font-size: var(--text-2xl);
		color: var(--text-primary);
	}
	h2 {
		margin: 0 0 var(--space-2) 0;
		font-size: var(--text-lg);
		color: var(--text-primary);
	}
	.hint {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-4) 0;
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
	}
	:global(.card) + :global(.card) {
		margin-top: var(--space-4);
	}
	form {
		display: flex;
		flex-direction: column;
		max-width: 24rem;
	}
	.campo {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		margin-bottom: var(--space-4);
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.lista {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.lista li {
		display: flex;
		justify-content: space-between;
		align-items: center;
		gap: var(--space-4);
		padding: var(--space-3);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-md);
	}
	.info {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.secundario {
		color: var(--text-secondary);
		font-size: var(--text-sm);
	}
	.acciones {
		display: flex;
		gap: var(--space-2);
		flex-wrap: wrap;
	}
	.huella {
		margin-top: var(--space-4);
		max-width: 32rem;
	}
	.mono {
		font-family: var(--font-mono, monospace);
		font-size: var(--text-lg);
	}
	.confirmar {
		display: flex;
		gap: var(--space-2);
		align-items: center;
		margin-bottom: var(--space-4);
		font-size: var(--text-sm);
	}
</style>
