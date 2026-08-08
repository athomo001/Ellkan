<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-05/F-06/F-07/F-08/F-11: Vault real — listado con metadata descifrada
	// client-side, creación de recursos personales, ver secreto (F-39: campo
	// enmascarado + copiar con limpieza de portapapeles) y compartir
	// (sólo recursos `shared_key`, el backend rechaza compartir `user_key`).
	//
	// **Editar no está implementado** — no hay `PUT`/`PATCH /resources/{id}`
	// en el backend, y "editar" un recurso compartido exigiría re-sellar el
	// secreto para cada destinatario ya existente sin que exista ningún
	// endpoint que liste esos destinatarios. Gap real de backend, ver
	// `$lib/crypto/recursos.ts` y `docs/pendientesVerificacionReal.md`.
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import SecretField from '$lib/components/SecretField.svelte';
	import FolderTree from '$lib/components/FolderTree.svelte';
	import TagFilterBar from '$lib/components/TagFilterBar.svelte';
	import {
		listarRecursos,
		verSecreto,
		crearRecurso,
		editarRecurso,
		compartirRecurso,
		type Recurso
	} from '$lib/crypto/recursos';
	import { listarArbolCarpetas, crearCarpeta, moverCarpeta, type NodoCarpeta } from '$lib/crypto/carpetas';
	import { tagsApi, type Tag } from '$lib/api/tags';
	import { desbloquearConPassphrase } from '$lib/crypto/identity';
	import { conDeduplicacion, refrescarAlEnfocar, huboCambios } from '$lib/api/sync';
	import { sesion, clavesDesbloqueadas } from '$lib/state/session';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let cargando = $state(true);
	let error = $state<string | undefined>();
	let recursos = $state<Recurso[]>([]);

	// --- carpetas (F-09) + tags (F-10) — organización del vault ---
	let carpetas = $state<NodoCarpeta[]>([]);
	let cargandoCarpetas = $state(true);
	let errorCarpetas = $state<string | undefined>();
	let tags = $state<Tag[]>([]);
	let cargandoTags = $state(true);
	let errorTags = $state<string | undefined>();
	let tagsSeleccionados = $state<string[]>([]);
	let idsConTagsSeleccionados = $state<Set<string> | null>(null);
	let busqueda = $state('');

	async function cargarOrganizacion() {
		if (!$clavesDesbloqueadas) return;
		cargandoCarpetas = true;
		errorCarpetas = undefined;
		try {
			carpetas = await listarArbolCarpetas($clavesDesbloqueadas);
		} catch (err) {
			errorCarpetas = err instanceof ApiError ? err.message : $t.vault.carpetas.error;
		} finally {
			cargandoCarpetas = false;
		}

		cargandoTags = true;
		errorTags = undefined;
		try {
			tags = await tagsApi.listar();
		} catch (err) {
			errorTags = err instanceof ApiError ? err.message : $t.vault.tags.error;
		} finally {
			cargandoTags = false;
		}
	}

	async function onCrearCarpeta(nombreCarpeta: string, parentId: string | null) {
		if (!$clavesDesbloqueadas) return;
		try {
			const nueva = await crearCarpeta(nombreCarpeta, parentId, $clavesDesbloqueadas);
			carpetas = [...carpetas, nueva];
		} catch (err) {
			errorCarpetas = err instanceof ApiError ? err.message : $t.vault.carpetas.errorCrear;
		}
	}

	async function onMoverCarpeta(folderId: string, newParentId: string | null) {
		try {
			await moverCarpeta(folderId, newParentId);
			carpetas = carpetas.map((c) => (c.id === folderId ? { ...c, parentId: newParentId } : c));
		} catch (err) {
			errorCarpetas = err instanceof ApiError ? err.message : $t.vault.carpetas.error;
		}
	}

	async function onCrearTag(nombreTag: string, isShared: boolean) {
		try {
			const nuevo = await tagsApi.crear(nombreTag, isShared);
			tags = [...tags, nuevo];
		} catch (err) {
			errorTags = err instanceof ApiError ? err.message : $t.vault.tags.errorCrear;
		}
	}

	// Filtro por tag: intersección de los ids de cada tag seleccionado
	// (semántica AND) — se recalcula cuando cambia la selección, nunca
	// re-descifra nada (`recursos` ya está descifrado por `cargar()`).
	$effect(() => {
		const seleccion = tagsSeleccionados;
		if (seleccion.length === 0) {
			idsConTagsSeleccionados = null;
			return;
		}
		let cancelado = false;
		Promise.all(seleccion.map((id) => tagsApi.idsConTag(id))).then((listas) => {
			if (cancelado) return;
			const [primera, ...resto] = listas.map((l) => new Set(l));
			idsConTagsSeleccionados = resto.reduce((acc, s) => new Set([...acc].filter((id) => s.has(id))), primera);
		});
		return () => {
			cancelado = true;
		};
	});

	const recursosFiltrados = $derived(
		recursos.filter((r) => {
			if (idsConTagsSeleccionados && !idsConTagsSeleccionados.has(r.id)) return false;
			if (!busqueda.trim()) return true;
			const q = busqueda.trim().toLowerCase();
			return r.nombre.toLowerCase().includes(q) || r.usuario.toLowerCase().includes(q) || r.uri.toLowerCase().includes(q);
		})
	);

	// Passkey sin PRF deja `clavesDesbloqueadas` vacío tras el login (spec
	// F-03: la passphrase sigue haciendo falta para operaciones sobre
	// recursos) — acá es donde efectivamente hace falta, se pide una vez.
	let passphraseDesbloqueo = $state('');
	let desbloqueando = $state(false);
	let errorDesbloqueo = $state<string | undefined>();

	async function cargar() {
		if (!$clavesDesbloqueadas) return;
		cargando = true;
		error = undefined;
		try {
			// `conDeduplicacion` (07-frontend-web.md §2): si el refresco por
			// foco de pestaña dispara mientras ya hay una carga en curso (ej.
			// el usuario cambia de pestaña y vuelve rápido), la segunda
			// llamada espera la primera en vez de disparar una request nueva.
			const nuevos = await conDeduplicacion('vault:listar', () => listarRecursos($clavesDesbloqueadas!));
			// F-30: si nada cambió (mismo conteo, mismo `updated_at` más
			// reciente), no reemplaza la lista — preserva estado de UI local
			// (ej. una fila expandida) en un refresco por foco sin cambios
			// reales.
			if (huboCambios(recursos, nuevos)) recursos = nuevos;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.vault.error;
		} finally {
			cargando = false;
		}
	}

	onMount(() => {
		cargar();
		cargarOrganizacion();
		// F-30 (07-frontend-web.md §2): recargar al volver a la pestaña, sin
		// polling — cubre el caso de compartir/crear un recurso desde otro
		// dispositivo mientras esta pestaña quedó abierta en segundo plano.
		return refrescarAlEnfocar(cargar);
	});

	async function desbloquear(e: SubmitEvent) {
		e.preventDefault();
		errorDesbloqueo = undefined;
		desbloqueando = true;
		try {
			clavesDesbloqueadas.set(await desbloquearConPassphrase($sesion.email ?? '', passphraseDesbloqueo));
			passphraseDesbloqueo = '';
			await cargar();
			await cargarOrganizacion();
		} catch {
			errorDesbloqueo = $t.lockOverlay.errorPassphrase;
		} finally {
			desbloqueando = false;
		}
	}

	// --- crear ---
	let mostrarCrear = $state(false);
	let nombre = $state('');
	let usuario = $state('');
	let uri = $state('');
	let password = $state('');
	let notas = $state('');
	let totpSecretBase32 = $state('');
	let creando = $state(false);
	let errorCrear = $state<string | undefined>();

	async function crear(e: SubmitEvent) {
		e.preventDefault();
		if (!$clavesDesbloqueadas || !$sesion.userId) return;
		errorCrear = undefined;
		creando = true;
		try {
			await crearRecurso(
				{ nombre, usuario, uri, password, notas, totpSecretBase32: totpSecretBase32 || undefined },
				$clavesDesbloqueadas,
				$sesion.userId
			);
			nombre = usuario = uri = password = notas = totpSecretBase32 = '';
			mostrarCrear = false;
			await cargar();
		} catch (err) {
			errorCrear = err instanceof ApiError ? err.message : $t.vault.errorCrear;
		} finally {
			creando = false;
		}
	}

	// --- ver secreto ---
	let abiertoId = $state<string | undefined>();
	let secretoAbierto = $state<{ password: string; notes: string; totpSecret?: string } | undefined>();
	let cargandoSecreto = $state(false);
	let errorSecreto = $state<string | undefined>();

	async function toggleVerSecreto(recurso: Recurso) {
		if (abiertoId === recurso.id) {
			abiertoId = undefined;
			secretoAbierto = undefined;
			return;
		}
		if (!$clavesDesbloqueadas) return;
		errorSecreto = undefined;
		cargandoSecreto = true;
		abiertoId = recurso.id;
		try {
			secretoAbierto = await verSecreto(recurso, $clavesDesbloqueadas);
		} catch (err) {
			errorSecreto = err instanceof ApiError ? err.message : $t.vault.errorVerSecreto;
		} finally {
			cargandoSecreto = false;
		}
	}

	// --- editar (F-07, sólo user_key por ahora, ver recursos.ts::editarRecurso) ---
	let editandoId = $state<string | undefined>();
	let editNombre = $state('');
	let editUsuario = $state('');
	let editUri = $state('');
	let editPassword = $state('');
	let editNotas = $state('');
	let editTotp = $state('');
	let cargandoParaEditar = $state(false);
	let guardandoEdicion = $state(false);
	let errorEditar = $state<string | undefined>();

	async function empezarEditar(recurso: Recurso) {
		if (editandoId === recurso.id) {
			editandoId = undefined;
			return;
		}
		if (!$clavesDesbloqueadas) return;
		errorEditar = undefined;
		editandoId = recurso.id;
		cargandoParaEditar = true;
		try {
			const secreto = await verSecreto(recurso, $clavesDesbloqueadas);
			editNombre = recurso.nombre;
			editUsuario = recurso.usuario;
			editUri = recurso.uri;
			editPassword = secreto.password;
			editNotas = secreto.notes;
			editTotp = secreto.totpSecret ?? '';
		} catch (err) {
			errorEditar = err instanceof ApiError ? err.message : $t.vault.errorVerSecreto;
		} finally {
			cargandoParaEditar = false;
		}
	}

	async function guardarEdicion(e: SubmitEvent, recurso: Recurso) {
		e.preventDefault();
		if (!$clavesDesbloqueadas) return;
		errorEditar = undefined;
		guardandoEdicion = true;
		try {
			const actualizado = await editarRecurso(
				recurso,
				{
					nombre: editNombre,
					usuario: editUsuario,
					uri: editUri,
					password: editPassword,
					notas: editNotas,
					totpSecretBase32: editTotp || undefined
				},
				$clavesDesbloqueadas
			);
			recursos = recursos.map((r) => (r.id === recurso.id ? actualizado : r));
			editandoId = undefined;
		} catch (err) {
			errorEditar = err instanceof ApiError ? err.message : $t.vault.errorEditar;
		} finally {
			guardandoEdicion = false;
		}
	}

	// --- compartir ---
	let compartiendoId = $state<string | undefined>();
	let emailCompartir = $state('');
	let enviandoCompartir = $state(false);
	let errorCompartir = $state<string | undefined>();
	let compartidoOk = $state(false);

	function toggleCompartir(recurso: Recurso) {
		compartiendoId = compartiendoId === recurso.id ? undefined : recurso.id;
		emailCompartir = '';
		errorCompartir = undefined;
		compartidoOk = false;
	}

	async function enviarCompartir(e: SubmitEvent, recurso: Recurso) {
		e.preventDefault();
		if (!$clavesDesbloqueadas) return;
		errorCompartir = undefined;
		enviandoCompartir = true;
		try {
			await compartirRecurso(recurso, emailCompartir, $clavesDesbloqueadas);
			compartidoOk = true;
			emailCompartir = '';
		} catch (err) {
			errorCompartir = err instanceof ApiError ? err.message : $t.vault.errorCompartir;
		} finally {
			enviandoCompartir = false;
		}
	}
</script>

<svelte:head>
	<title>{$t.vault.titulo} — Ellkan</title>
</svelte:head>

<h1>{$t.vault.titulo}</h1>

{#if !$clavesDesbloqueadas}
	<Card>
		<form onsubmit={desbloquear}>
			<TextField
				label={$t.lockOverlay.passphrase}
				type="password"
				bind:value={passphraseDesbloqueo}
				autocomplete="current-password"
				required
			/>
			{#if errorDesbloqueo}<p class="error">{errorDesbloqueo}</p>{/if}
			<Button type="submit" variant="primary" loading={desbloqueando}>{$t.lockOverlay.desbloquear}</Button>
		</form>
	</Card>
{:else}
	<div class="vault-layout">
		<Card padded={true}>
			<FolderTree
				nodos={carpetas}
				cargando={cargandoCarpetas}
				onCrear={onCrearCarpeta}
				onMover={onMoverCarpeta}
			/>
			{#if errorCarpetas}<p class="error">{errorCarpetas}</p>{/if}
		</Card>
	<Card>
		{#if cargando}
			<p>{$t.vault.cargando}</p>
		{:else if error}
			<p class="error">{error}</p>
		{:else}
			<div class="cabecera">
				<p class="conteo">{$t.vault.conteo(recursosFiltrados.length)}</p>
				<Button variant="primary" onclick={() => (mostrarCrear = !mostrarCrear)}>{$t.vault.nuevoRecurso}</Button>
			</div>

			<TextField label={$t.vault.buscar} bind:value={busqueda} />
			<TagFilterBar tags={tags} bind:seleccionados={tagsSeleccionados} cargando={cargandoTags} onCrear={onCrearTag} />
			{#if errorTags}<p class="error">{errorTags}</p>{/if}

			{#if mostrarCrear}
				<form onsubmit={crear} class="crear">
					<TextField label={$t.vault.nombre} bind:value={nombre} required />
					<TextField label={$t.vault.usuario} bind:value={usuario} />
					<TextField label={$t.vault.uri} bind:value={uri} />
					<TextField label={$t.vault.password} type="password" bind:value={password} required />
					<TextField label={$t.vault.notas} bind:value={notas} />
					<TextField label={$t.vault.totpOpcional} bind:value={totpSecretBase32} />
					{#if errorCrear}<p class="error">{errorCrear}</p>{/if}
					<div class="botones">
						<Button type="submit" variant="primary" loading={creando}>{$t.vault.crear}</Button>
						<Button type="button" variant="ghost" onclick={() => (mostrarCrear = false)}>{$t.vault.cancelar}</Button>
					</div>
				</form>
			{/if}

			{#if recursosFiltrados.length === 0 && !mostrarCrear}
				<p class="hint">{$t.vault.sinRecursos}</p>
			{/if}

			<ul class="lista">
				{#each recursosFiltrados as recurso (recurso.id)}
					<li class="item">
						<div class="info">
							<strong>{recurso.nombre}</strong>
							<span class="secundario">{recurso.usuario}</span>
							{#if recurso.uri}<span class="secundario">{recurso.uri}</span>{/if}
						</div>
						<div class="acciones">
							<Button variant="secondary" onclick={() => toggleVerSecreto(recurso)}>
								{abiertoId === recurso.id ? $t.vault.ocultarSecreto : $t.vault.verSecreto}
							</Button>
							{#if recurso.metadataKeyType === 'shared_key'}
								<Button variant="ghost" onclick={() => toggleCompartir(recurso)}>{$t.vault.compartir}</Button>
							{:else}
								<Button variant="ghost" onclick={() => empezarEditar(recurso)} loading={cargandoParaEditar && editandoId === recurso.id}>
									{$t.vault.editar}
								</Button>
								<span class="badge">{$t.vault.personal}</span>
							{/if}
						</div>

						{#if editandoId === recurso.id && !cargandoParaEditar}
							<form onsubmit={(e) => guardarEdicion(e, recurso)} class="detalle">
								<TextField label={$t.vault.nombre} bind:value={editNombre} required />
								<TextField label={$t.vault.usuario} bind:value={editUsuario} />
								<TextField label={$t.vault.uri} bind:value={editUri} />
								<TextField label={$t.vault.password} type="password" bind:value={editPassword} required />
								<TextField label={$t.vault.notas} bind:value={editNotas} />
								<TextField label={$t.vault.totpOpcional} bind:value={editTotp} />
								{#if errorEditar}<p class="error">{errorEditar}</p>{/if}
								<Button type="submit" variant="primary" loading={guardandoEdicion}>{$t.vault.guardarEdicion}</Button>
							</form>
						{/if}

						{#if abiertoId === recurso.id}
							<div class="detalle">
								{#if cargandoSecreto}
									<p>{$t.vault.cargando}</p>
								{:else if errorSecreto}
									<p class="error">{errorSecreto}</p>
								{:else if secretoAbierto}
									<SecretField label={$t.vault.password} valor={secretoAbierto.password} />
									{#if secretoAbierto.notes}
										<p class="notas">{secretoAbierto.notes}</p>
									{/if}
									{#if secretoAbierto.totpSecret}
										<SecretField label="TOTP" valor={secretoAbierto.totpSecret} />
									{/if}
								{/if}
							</div>
						{/if}

						{#if compartiendoId === recurso.id}
							<form onsubmit={(e) => enviarCompartir(e, recurso)} class="detalle">
								<TextField label={$t.vault.compartirCon} type="email" bind:value={emailCompartir} required />
								{#if errorCompartir}<p class="error">{errorCompartir}</p>{/if}
								{#if compartidoOk}<p class="ok">{$t.vault.compartido}</p>{/if}
								<Button type="submit" variant="primary" loading={enviandoCompartir}
									>{$t.vault.enviarCompartir}</Button
								>
							</form>
						{/if}
					</li>
				{/each}
			</ul>
		{/if}
	</Card>
	</div>
{/if}

<style>
	h1 {
		margin: 0 0 var(--space-6) 0;
		font-size: var(--text-2xl);
		color: var(--text-primary);
	}
	.vault-layout {
		display: grid;
		grid-template-columns: 14rem 1fr;
		gap: var(--space-4);
		align-items: start;
	}
	.cabecera {
		display: flex;
		align-items: center;
		justify-content: space-between;
		margin-bottom: var(--space-4);
	}
	.conteo {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin: 0;
	}
	.hint {
		color: var(--text-muted);
		font-size: var(--text-sm);
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
	}
	.ok {
		color: var(--success);
		font-size: var(--text-sm);
	}
	form.crear,
	form.detalle {
		display: flex;
		flex-direction: column;
		max-width: 24rem;
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-4);
		margin-bottom: var(--space-4);
	}
	.botones {
		display: flex;
		gap: var(--space-2);
	}
	.lista {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.item {
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-3) var(--space-4);
	}
	.info {
		display: flex;
		flex-direction: column;
		gap: 2px;
	}
	.secundario {
		color: var(--text-muted);
		font-size: var(--text-sm);
	}
	.acciones {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		margin-top: var(--space-2);
	}
	.badge {
		font-size: var(--text-xs);
		color: var(--text-muted);
	}
	.detalle {
		margin-top: var(--space-3);
	}
	.notas {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		white-space: pre-wrap;
	}
</style>
