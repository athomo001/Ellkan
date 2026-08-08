<!-- Autor: Athan Espinoza -->
<script lang="ts">
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import Table from '$lib/components/Table.svelte';
	import { groupsApi, type Grupo, type EnvelopeParaGrupo } from '$lib/api/admin';
	import { resellarSecretoParaGrupo } from '$lib/crypto/recursos';
	import { desbloquearConPassphrase } from '$lib/crypto/identity';
	import { sesion, clavesDesbloqueadas } from '$lib/state/session';
	import { t } from '$lib/i18n';
	import { api, ApiError } from '$lib/api/client';

	let cargando = $state(true);
	let error = $state<string | undefined>();
	let grupos = $state<Grupo[]>([]);

	async function cargar() {
		cargando = true;
		error = undefined;
		try {
			grupos = await groupsApi.listar();
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			cargando = false;
		}
	}
	onMount(cargar);

	let mostrarNuevo = $state(false);
	let nombreNuevo = $state('');
	let creando = $state(false);

	async function crear(e: SubmitEvent) {
		e.preventDefault();
		creando = true;
		error = undefined;
		try {
			await groupsApi.crear(crypto.randomUUID(), nombreNuevo);
			nombreNuevo = '';
			mostrarNuevo = false;
			await cargar();
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			creando = false;
		}
	}

	let abiertoId = $state<string | undefined>();
	let detalle = $state<Grupo | undefined>();
	let nuevoMiembroEmail = $state('');
	let nuevoMiembroAdmin = $state(false);
	let agregandoMiembro = $state(false);

	// F-12: recursos que el grupo abierto ya comparte — si hay alguno, hace
	// falta la passphrase para re-sellar antes de poder agregar un miembro.
	let recursosDelGrupo = $state<string[]>([]);
	let passphraseResellado = $state('');
	let desbloqueando = $state(false);
	let errorDesbloqueo = $state<string | undefined>();

	async function toggleDetalle(g: Grupo) {
		if (abiertoId === g.id) {
			abiertoId = undefined;
			detalle = undefined;
			recursosDelGrupo = [];
			return;
		}
		abiertoId = g.id;
		detalle = await groupsApi.obtener(g.id);
		recursosDelGrupo = await groupsApi.recursosCompartidos(g.id);
	}

	async function desbloquear(e: SubmitEvent) {
		e.preventDefault();
		errorDesbloqueo = undefined;
		desbloqueando = true;
		try {
			clavesDesbloqueadas.set(await desbloquearConPassphrase($sesion.email ?? '', passphraseResellado));
			passphraseResellado = '';
		} catch {
			errorDesbloqueo = $t.lockOverlay.errorPassphrase;
		} finally {
			desbloqueando = false;
		}
	}

	async function agregarMiembro(e: SubmitEvent) {
		e.preventDefault();
		if (!abiertoId) return;
		agregandoMiembro = true;
		error = undefined;
		try {
			const destinatario = await api.get<{ user_id: string; public_key_x25519_b64: string }>(
				`/users/${encodeURIComponent(nuevoMiembroEmail)}/public-key`
			);

			let envelopes: EnvelopeParaGrupo[] = [];
			if (recursosDelGrupo.length > 0) {
				if (!$clavesDesbloqueadas) throw new Error($t.admin.grupos.errorSinDesbloquear);
				envelopes = await Promise.all(
					recursosDelGrupo.map((resourceId) =>
						resellarSecretoParaGrupo(resourceId, $clavesDesbloqueadas!, destinatario.public_key_x25519_b64)
					)
				);
			}

			await groupsApi.agregarMiembro(abiertoId, destinatario.user_id, nuevoMiembroAdmin, envelopes);
			nuevoMiembroEmail = '';
			detalle = await groupsApi.obtener(abiertoId);
		} catch (err) {
			error = err instanceof ApiError || err instanceof Error ? err.message : $t.admin.grupos.errorEnvelopes;
		} finally {
			agregandoMiembro = false;
		}
	}

	async function quitarMiembro(userId: string) {
		if (!abiertoId) return;
		await groupsApi.quitarMiembro(abiertoId, userId);
		detalle = await groupsApi.obtener(abiertoId);
	}

	async function eliminarGrupo(id: string) {
		await groupsApi.eliminar(id);
		abiertoId = undefined;
		detalle = undefined;
		await cargar();
	}
</script>

<h1>{$t.admin.grupos.titulo}</h1>
<Card>
	{#if cargando}
		<p>{$t.admin.comun.cargando}</p>
	{:else}
		{#if error}<p class="error">{error}</p>{/if}

		<div class="cabecera">
			<Button variant="primary" onclick={() => (mostrarNuevo = !mostrarNuevo)}>{$t.admin.grupos.nuevoGrupo}</Button>
		</div>

		{#if mostrarNuevo}
			<form onsubmit={crear} class="form">
				<TextField label={$t.admin.grupos.nombre} bind:value={nombreNuevo} required />
				<Button type="submit" variant="primary" loading={creando}>{$t.admin.comun.crear}</Button>
			</form>
		{/if}

		<Table
			columnas={[
				{ key: 'nombre', header: $t.admin.grupos.nombre },
				{ key: 'padre', header: $t.admin.grupos.colPadre },
				{ key: 'acciones', header: '' }
			]}
			filas={grupos}
			claveFila={(f) => f.id}
			vacio={$t.admin.grupos.sinGrupos}
			seleccionadaId={abiertoId}
			onSeleccionar={toggleDetalle}
		>
			{#snippet fila(g)}
				<td>{g.name}</td>
				<td class="secundario">{g.parent_group_id ?? $t.admin.grupos.grupoRaiz}</td>
				<td>
					<Button variant="danger" onclick={(e) => { e.stopPropagation(); eliminarGrupo(g.id); }}>
						{$t.admin.grupos.eliminarGrupo}
					</Button>
				</td>
			{/snippet}
		</Table>

		{#if abiertoId && detalle}
			<div class="detalle">
				<h2>{$t.admin.grupos.miembros}</h2>
				<ul>
					{#each detalle.members as m (m.user_id)}
						<li class="miembro">
							<span>{m.user_id}{m.is_admin ? ` (${$t.admin.grupos.admin})` : ''}</span>
							<button type="button" class="link" onclick={() => quitarMiembro(m.user_id)}>{$t.admin.grupos.quitar}</button>
						</li>
					{/each}
				</ul>
				{#if recursosDelGrupo.length > 0 && !$clavesDesbloqueadas}
					<form onsubmit={desbloquear} class="form-inline">
						<TextField
							label={$t.lockOverlay.passphrase}
							type="password"
							bind:value={passphraseResellado}
							autocomplete="current-password"
							required
						/>
						<Button type="submit" variant="secondary" loading={desbloqueando}>{$t.lockOverlay.desbloquear}</Button>
					</form>
					{#if errorDesbloqueo}<p class="error">{errorDesbloqueo}</p>{/if}
					<p class="hint">{$t.admin.grupos.hintResellado}</p>
				{:else}
					<form onsubmit={agregarMiembro} class="form-inline">
						<TextField label={$t.admin.grupos.agregarMiembro} type="email" bind:value={nuevoMiembroEmail} required />
						<label class="check">
							<input type="checkbox" bind:checked={nuevoMiembroAdmin} /> {$t.admin.grupos.admin}
						</label>
						<Button type="submit" variant="primary" loading={agregandoMiembro}>{$t.admin.comun.crear}</Button>
					</form>
					{#if recursosDelGrupo.length > 0}
						<p class="hint">{$t.admin.grupos.hintResellado}</p>
					{/if}
				{/if}
			</div>
		{/if}
	{/if}
</Card>

<style>
	h1 {
		margin: 0 0 var(--space-6) 0;
		font-size: var(--text-2xl);
		color: var(--text-primary);
	}
	.cabecera {
		margin-bottom: var(--space-4);
	}
	.form,
	.form-inline {
		display: flex;
		align-items: flex-end;
		gap: var(--space-2);
		max-width: 28rem;
		margin-bottom: var(--space-4);
	}
	.secundario {
		color: var(--text-muted);
		font-size: var(--text-sm);
	}
	.detalle {
		margin-top: var(--space-4);
		border-top: 1px solid var(--border-color);
		padding-top: var(--space-4);
	}
	.detalle h2 {
		margin: 0 0 var(--space-3) 0;
		font-size: var(--text-sm);
		text-transform: uppercase;
		letter-spacing: 0.04em;
		color: var(--text-muted);
	}
	.miembro {
		display: flex;
		align-items: center;
		justify-content: space-between;
		font-size: var(--text-sm);
		padding: var(--space-1) 0;
	}
	.check {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		white-space: nowrap;
	}
	.hint {
		color: var(--text-muted);
		font-size: var(--text-xs);
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
	}
	.link {
		background: none;
		border: none;
		padding: 0;
		font-size: var(--text-sm);
		color: var(--accent-primary);
		cursor: pointer;
	}
</style>
