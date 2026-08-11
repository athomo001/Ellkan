<!-- Autor: Athan Espinoza -->
<script lang="ts">
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import Table from '$lib/components/Table.svelte';
	import { groupsApi, usersAdminApi, type Grupo, type EnvelopeParaGrupo, type UsuarioAdmin } from '$lib/api/admin';
	import { resellarSecretoParaGrupo } from '$lib/crypto/recursos';
	import { desbloquearConPassphrase } from '$lib/crypto/identity';
	import { sesion, clavesDesbloqueadas } from '$lib/state/session';
	import { t } from '$lib/i18n';
	import { api, ApiError } from '$lib/api/client';

	let cargando = $state(true);
	let error = $state<string | undefined>();
	let grupos = $state<Grupo[]>([]);

	// Selector de miembros (en vez de un campo de texto libre): se carga una
	// sola vez, todas las páginas de `GET /admin/users` — alcanza para el
	// tamaño típico de una organización que usa este panel, y evita tener
	// que armar un combobox con búsqueda remota sólo para esto.
	let usuarios = $state<UsuarioAdmin[]>([]);
	async function cargarUsuarios() {
		let cursor: string | undefined;
		const todos: UsuarioAdmin[] = [];
		do {
			const pagina = await usersAdminApi.listar(cursor);
			todos.push(...pagina.items);
			cursor = pagina.next_cursor ?? undefined;
		} while (cursor);
		usuarios = todos;
	}

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
	onMount(() => {
		cargar();
		cargarUsuarios();
	});

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

	/** Usada por el alta individual y por la carga CSV — devuelve el error
	 * como string en vez de lanzar, para que el loop del CSV no aborte todo
	 * el batch por un solo email fallido. */
	async function agregarMiembroPorEmail(email: string, isAdmin: boolean): Promise<string | undefined> {
		if (!abiertoId) return undefined;
		try {
			const destinatario = await api.get<{ user_id: string; public_key_x25519_b64: string }>(
				`/users/${encodeURIComponent(email)}/public-key`
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

			await groupsApi.agregarMiembro(abiertoId, destinatario.user_id, isAdmin, envelopes);
			return undefined;
		} catch (err) {
			return err instanceof ApiError || err instanceof Error ? err.message : $t.admin.grupos.errorEnvelopes;
		}
	}

	async function agregarMiembro(e: SubmitEvent) {
		e.preventDefault();
		if (!abiertoId) return;
		agregandoMiembro = true;
		error = undefined;
		const fallo = await agregarMiembroPorEmail(nuevoMiembroEmail, nuevoMiembroAdmin);
		if (fallo) {
			error = fallo;
		} else {
			nuevoMiembroEmail = '';
			detalle = await groupsApi.obtener(abiertoId);
		}
		agregandoMiembro = false;
	}

	// Carga CSV: una columna de emails (separados por línea o coma) — no
	// hace falta el parser RFC4180 completo de `exportCsv.ts` (eso es para
	// campos con comillas/comas adentro, como notas; una lista de emails no
	// las necesita).
	let cargandoCsv = $state(false);
	let resumenCsv = $state<{ agregados: number; fallidos: { email: string; motivo: string }[] } | undefined>();

	async function cargarCsv(e: Event) {
		const input = e.currentTarget as HTMLInputElement;
		const archivo = input.files?.[0];
		if (!archivo || !abiertoId) return;

		const texto = await archivo.text();
		const emails = [...new Set(texto.split(/[\n,]/).map((s) => s.trim()).filter(Boolean))];

		cargandoCsv = true;
		resumenCsv = undefined;
		error = undefined;
		const fallidos: { email: string; motivo: string }[] = [];
		let agregados = 0;
		for (const email of emails) {
			const fallo = await agregarMiembroPorEmail(email, false);
			if (fallo) fallidos.push({ email, motivo: fallo });
			else agregados++;
		}
		resumenCsv = { agregados, fallidos };
		if (agregados > 0) detalle = await groupsApi.obtener(abiertoId);
		cargandoCsv = false;
		input.value = '';
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
							<span>{m.display_name || m.email}{m.is_admin ? ` (${$t.admin.grupos.admin})` : ''}</span>
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
						<div class="field-con-datalist">
							<label for="miembro-email">{$t.admin.grupos.agregarMiembro}</label>
							<input
								id="miembro-email"
								type="email"
								list="usuarios-existentes"
								bind:value={nuevoMiembroEmail}
								required
							/>
							<datalist id="usuarios-existentes">
								{#each usuarios as u (u.id)}
									<option value={u.email}>{u.display_name}</option>
								{/each}
							</datalist>
						</div>
						<label class="check">
							<input type="checkbox" bind:checked={nuevoMiembroAdmin} /> {$t.admin.grupos.admin}
						</label>
						<Button type="submit" variant="primary" loading={agregandoMiembro}>{$t.admin.comun.crear}</Button>
					</form>
					{#if recursosDelGrupo.length > 0}
						<p class="hint">{$t.admin.grupos.hintResellado}</p>
					{/if}

					<div class="carga-csv">
						<label for="csv-miembros" class="link">{$t.admin.grupos.cargarCsv}</label>
						<input id="csv-miembros" type="file" accept=".csv,text/csv" onchange={cargarCsv} disabled={cargandoCsv} />
						{#if cargandoCsv}<span class="hint">{$t.admin.comun.cargando}</span>{/if}
					</div>
					{#if resumenCsv}
						<p class="hint">
							{$t.admin.grupos.resumenCsv(resumenCsv.agregados, resumenCsv.fallidos.length)}
						</p>
						{#if resumenCsv.fallidos.length > 0}
							<ul class="fallidos-csv">
								{#each resumenCsv.fallidos as f (f.email)}
									<li>{f.email}: {f.motivo}</li>
								{/each}
							</ul>
						{/if}
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
	.form :global(.field),
	.form-inline :global(.field) {
		margin-bottom: 0;
	}
	.field-con-datalist {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
	}
	.field-con-datalist label {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		font-weight: 500;
	}
	.field-con-datalist input {
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
		color: var(--text-primary);
	}
	.carga-csv {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		margin: var(--space-2) 0 var(--space-4) 0;
	}
	.fallidos-csv {
		margin: 0 0 var(--space-4) 0;
		padding-left: var(--space-4);
		font-size: var(--text-sm);
		color: var(--danger);
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
