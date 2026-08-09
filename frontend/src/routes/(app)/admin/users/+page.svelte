<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-20/F-40: no hay `GET /admin/users` (listado completo) en el backend
	// — gap real (F-29, exportación masiva, sigue sin implementar en 1.6).
	// Se busca por email vía `/users/{email}/public-key` (ya devuelve
	// `user_id`) y de ahí se opera sobre ese usuario puntual.
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import SecretField from '$lib/components/SecretField.svelte';
	import Table from '$lib/components/Table.svelte';
	import { usersAdminApi, type UsuarioAdmin, type PurgeDryRun } from '$lib/api/admin';
	import { registrar } from '$lib/crypto/identity';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	// Parte C: reusa la misma ceremonia de F-01 que la pantalla pública de
	// registro (`(anon)/register/+page.svelte::enviar`) — corre en el propio
	// navegador del admin, para la identidad del usuario nuevo. Cero cambios
	// de backend: Ellkan es zero-knowledge, el servidor no puede generar la
	// clave privada cifrada de otra persona. Crea sólo rol 'user' — promover
	// a admin sigue exigiendo `ellkan-cli admin promote-to-admin`
	// (frontera de seguridad deliberada, no se toca acá).
	let nuevoEmail = $state('');
	let nuevoNombre = $state('');
	let creandoUsuario = $state(false);
	let errorCrear = $state<string | undefined>();
	let passphraseCreada = $state<string | undefined>();

	function generarPassphraseTemporal(): string {
		const bytes = crypto.getRandomValues(new Uint8Array(20));
		return btoa(String.fromCharCode(...bytes)).replace(/[+/=]/g, '').slice(0, 24);
	}

	async function crearUsuario(e: SubmitEvent) {
		e.preventDefault();
		errorCrear = undefined;
		passphraseCreada = undefined;
		creandoUsuario = true;
		try {
			const passphrase = generarPassphraseTemporal();
			await registrar(nuevoEmail, nuevoNombre, passphrase);
			passphraseCreada = passphrase;
			nuevoEmail = '';
			nuevoNombre = '';
			await cargarListado(true);
		} catch (err) {
			errorCrear = err instanceof ApiError ? err.message : $t.admin.usuarios.errorCrear;
		} finally {
			creandoUsuario = false;
		}
	}

	// F-29: listado completo paginado (cursor-based, mismo patrón que
	// `AuditLogPage`) — además de la búsqueda por email de abajo, no en
	// reemplazo (buscar por email sigue siendo el camino rápido a un
	// usuario puntual).
	let listado = $state<UsuarioAdmin[]>([]);
	let cursorSiguiente = $state<string | undefined>();
	let cargandoListado = $state(false);
	let errorListado = $state<string | undefined>();

	async function cargarListado(desdeCero = false) {
		cargandoListado = true;
		errorListado = undefined;
		try {
			const pagina = await usersAdminApi.listar(desdeCero ? undefined : cursorSiguiente);
			listado = desdeCero ? pagina.items : [...listado, ...pagina.items];
			cursorSiguiente = pagina.next_cursor ?? undefined;
		} catch (err) {
			errorListado = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			cargandoListado = false;
		}
	}

	onMount(() => cargarListado(true));

	// --- Borrado masivo ---
	let seleccionados = $state<Set<string>>(new Set());
	let purgandoMasivo = $state(false);
	let resultadoMasivo = $state<{ ok: number; bloqueados: string[]; errores: string[] } | undefined>();

	function toggleSeleccion(id: string) {
		const nuevo = new Set(seleccionados);
		if (nuevo.has(id)) nuevo.delete(id);
		else nuevo.add(id);
		seleccionados = nuevo;
	}

	function toggleSeleccionTodos() {
		seleccionados = seleccionados.size === listado.length ? new Set() : new Set(listado.map((u) => u.id));
	}

	async function purgarSeleccionados() {
		if (seleccionados.size === 0) return;
		if (!confirm($t.admin.usuarios.purgaMasivaConfirmar(seleccionados.size))) return;
		purgandoMasivo = true;
		resultadoMasivo = undefined;
		const bloqueados: string[] = [];
		const errores: string[] = [];
		let ok = 0;
		// Secuencial, no Promise.all: cada purga es una transacción propia en
		// el servidor y así el rate limiter general (2/s) nunca se satura
		// con una tanda grande — también deja reportar exactamente cuál
		// usuario falló y por qué, no sólo "algo falló".
		for (const id of seleccionados) {
			const u = listado.find((x) => x.id === id);
			try {
				await usersAdminApi.purgar(id);
				ok++;
			} catch (err) {
				if (err instanceof ApiError && err.status === 409) {
					bloqueados.push(u?.email ?? id);
				} else {
					errores.push(u?.email ?? id);
				}
			}
		}
		resultadoMasivo = { ok, bloqueados, errores };
		seleccionados = new Set();
		purgandoMasivo = false;
		await cargarListado(true);
	}

	let email = $state('');
	let buscando = $state(false);
	let error = $state<string | undefined>();
	let usuario = $state<UsuarioAdmin | undefined>();

	async function buscar(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;
		usuario = undefined;
		dryRun = undefined;
		buscando = true;
		try {
			const { user_id } = await usersAdminApi.buscarPorEmail(email);
			usuario = await usersAdminApi.obtener(user_id);
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.usuarios.errorBuscar;
		} finally {
			buscando = false;
		}
	}

	async function seleccionarDeListado(fila: UsuarioAdmin) {
		error = undefined;
		dryRun = undefined;
		usuario = fila;
	}

	let cambiandoActivo = $state(false);
	async function toggleActivo() {
		if (!usuario) return;
		cambiandoActivo = true;
		try {
			usuario = await usersAdminApi.actualizarActivo(usuario.id, !usuario.active);
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			cambiandoActivo = false;
		}
	}

	let dryRun = $state<PurgeDryRun | undefined>();
	let cargandoDryRun = $state(false);
	async function verDryRun() {
		if (!usuario) return;
		cargandoDryRun = true;
		error = undefined;
		try {
			dryRun = await usersAdminApi.purgeDryRun(usuario.id);
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			cargandoDryRun = false;
		}
	}

	let purgando = $state(false);
	let purgaOk = $state<string | undefined>();
	async function purgar() {
		if (!usuario || !confirm($t.admin.usuarios.purgaConfirmar)) return;
		purgando = true;
		error = undefined;
		try {
			const r = await usersAdminApi.purgar(usuario.id);
			purgaOk = $t.admin.usuarios.purgaOk(r.resources_huerfanos_eliminados);
			usuario = undefined;
			dryRun = undefined;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			purgando = false;
		}
	}
</script>

<h1>{$t.admin.usuarios.titulo}</h1>

<Card>
	<h2>{$t.admin.usuarios.crearTitulo}</h2>
	<p class="hint">{$t.admin.usuarios.crearHint}</p>
	<form onsubmit={crearUsuario} class="form-crear">
		<TextField label={$t.admin.usuarios.nombre} bind:value={nuevoNombre} autocomplete="off" required />
		<TextField label={$t.admin.usuarios.email} type="email" bind:value={nuevoEmail} autocomplete="off" required />
		<Button type="submit" variant="primary" loading={creandoUsuario}>{$t.admin.usuarios.crear}</Button>
	</form>
	{#if errorCrear}<p class="error">{errorCrear}</p>{/if}
	{#if passphraseCreada}
		<div class="passphrase-creada">
			<p class="ok">{$t.admin.usuarios.creadoOk}</p>
			<SecretField label={$t.admin.usuarios.passphraseGenerada} valor={passphraseCreada} />
		</div>
	{/if}
</Card>

<Card>
	<h2>{$t.admin.usuarios.listadoTitulo}</h2>
	{#if errorListado}<p class="error">{errorListado}</p>{/if}

	<div class="barra-masiva">
		<Button variant="ghost" onclick={toggleSeleccionTodos} disabled={listado.length === 0}>
			{seleccionados.size === listado.length && listado.length > 0
				? $t.admin.usuarios.deseleccionarTodos
				: $t.admin.usuarios.seleccionarTodos}
		</Button>
		{#if seleccionados.size > 0}
			<Button variant="danger" onclick={purgarSeleccionados} loading={purgandoMasivo}>
				{$t.admin.usuarios.purgarSeleccionados(seleccionados.size)}
			</Button>
		{/if}
	</div>
	{#if resultadoMasivo}
		<p class="ok">{$t.admin.usuarios.purgaMasivaOk(resultadoMasivo.ok)}</p>
		{#if resultadoMasivo.bloqueados.length}
			<p class="error">{$t.admin.usuarios.purgaMasivaBloqueados}: {resultadoMasivo.bloqueados.join(', ')}</p>
		{/if}
		{#if resultadoMasivo.errores.length}
			<p class="error">{$t.admin.usuarios.purgaMasivaErrores}: {resultadoMasivo.errores.join(', ')}</p>
		{/if}
	{/if}

	<Table
		columnas={[
			{ key: 'sel', header: '' },
			{ key: 'nombre', header: $t.admin.usuarios.nombre },
			{ key: 'email', header: $t.admin.usuarios.email },
			{ key: 'estado', header: $t.admin.usuarios.estado }
		]}
		filas={listado}
		claveFila={(f) => f.id}
		cargando={cargandoListado}
		textoCargando={$t.admin.comun.cargando}
		vacio={$t.admin.usuarios.listadoVacio}
		seleccionadaId={usuario?.id}
		onSeleccionar={seleccionarDeListado}
	>
		{#snippet fila(f)}
			<td onclick={(e) => e.stopPropagation()}>
				<input type="checkbox" checked={seleccionados.has(f.id)} onchange={() => toggleSeleccion(f.id)} />
			</td>
			<td>{f.display_name}</td>
			<td>{f.email}</td>
			<td>{f.active ? $t.admin.usuarios.activo : $t.admin.usuarios.inactivo}</td>
		{/snippet}
	</Table>
	{#if cursorSiguiente}
		<Button variant="secondary" onclick={() => cargarListado(false)} loading={cargandoListado}>
			{$t.admin.auditoria.cargarMas}
		</Button>
	{/if}
</Card>

<Card>
	<h2>{$t.admin.usuarios.buscarTitulo}</h2>
	<p class="hint">{$t.admin.usuarios.hint}</p>
	<form onsubmit={buscar} class="form">
		<TextField label={$t.admin.usuarios.email} type="email" bind:value={email} required />
		<Button type="submit" variant="primary" loading={buscando}>{$t.admin.comun.buscar}</Button>
	</form>

	{#if error}<p class="error">{error}</p>{/if}
	{#if purgaOk}<p class="ok">{purgaOk}</p>{/if}

	{#if usuario}
		<div class="detalle">
			<p><strong>{usuario.display_name}</strong> — {usuario.email}</p>
			<p class="secundario">
				{usuario.active ? $t.admin.usuarios.activo : $t.admin.usuarios.inactivo}
			</p>
			<div class="botones">
				<Button variant="secondary" onclick={toggleActivo} loading={cambiandoActivo}>
					{usuario.active ? $t.admin.usuarios.desactivarCuenta : $t.admin.usuarios.activarCuenta}
				</Button>
				<Button variant="ghost" onclick={verDryRun} loading={cargandoDryRun}>{$t.admin.usuarios.verBloqueosPurga}</Button>
			</div>

			{#if dryRun}
				<div class="dryrun">
					{#if dryRun.blocks_purge}
						<p class="error">{$t.admin.usuarios.purgaBloqueada}</p>
						{#if dryRun.blocked_groups.length}
							<p class="secundario">{$t.admin.usuarios.gruposBloqueados}</p>
							<ul>
								{#each dryRun.blocked_groups as g (g.group_id)}<li>{g.name}</li>{/each}
							</ul>
						{/if}
						{#if dryRun.blocked_resources.length}
							<p class="secundario">{$t.admin.usuarios.recursosBloqueados}</p>
							<ul>
								{#each dryRun.blocked_resources as r (r)}<li>{r}</li>{/each}
							</ul>
						{/if}
					{:else}
						<p class="ok">{$t.admin.usuarios.sinBloqueos}</p>
						<Button variant="danger" onclick={purgar} loading={purgando}>{$t.admin.usuarios.purgar}</Button>
					{/if}
				</div>
			{/if}
		</div>
	{/if}
</Card>

<style>
	h1 {
		margin: 0 0 var(--space-6) 0;
		font-size: var(--text-2xl);
		color: var(--text-primary);
	}
	h2 {
		margin: 0 0 var(--space-3) 0;
		font-size: var(--text-lg);
		color: var(--text-primary);
	}
	:global(.card) + :global(.card) {
		margin-top: var(--space-4);
	}
	.hint {
		color: var(--text-muted);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-4) 0;
	}
	.barra-masiva {
		display: flex;
		gap: var(--space-2);
		margin-bottom: var(--space-3);
	}
	.form {
		display: flex;
		align-items: flex-end;
		gap: var(--space-2);
		max-width: 28rem;
	}
	.form-crear {
		display: flex;
		align-items: flex-end;
		gap: var(--space-2);
		flex-wrap: wrap;
		max-width: 34rem;
	}
	.form :global(.field),
	.form-crear :global(.field) {
		margin-bottom: 0;
	}
	.passphrase-creada {
		margin-top: var(--space-3);
		border-top: 1px solid var(--border-color);
		padding-top: var(--space-3);
	}
	.detalle {
		margin-top: var(--space-4);
		border-top: 1px solid var(--border-color);
		padding-top: var(--space-4);
	}
	.secundario {
		color: var(--text-muted);
		font-size: var(--text-sm);
	}
	.botones {
		display: flex;
		gap: var(--space-2);
		margin: var(--space-3) 0;
	}
	.dryrun {
		margin-top: var(--space-3);
		border-top: 1px solid var(--border-color);
		padding-top: var(--space-3);
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
