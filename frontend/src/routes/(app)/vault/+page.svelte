<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-05/F-06/F-07/F-08/F-11: Vault real — listado con metadata descifrada
	// client-side, creación de recursos personales, ver secreto (F-39: campo
	// enmascarado + copiar con limpieza de portapapeles), compartir (sólo
	// recursos `shared_key`) y editar (`user_key` solamente — editar
	// `shared_key` exige resolver la metadata key compartida, ver guard
	// explícito en `$lib/crypto/recursos.ts::editarRecurso`).
	//
	// Layout tabla + panel lateral de detalle (en vez de expansión inline
	// por fila) — un solo recurso seleccionado a la vez, `panelModo` decide
	// qué vista del panel mostrar. El secreto sigue sin decifrarse sólo por
	// seleccionar la fila: hace falta el botón "Ver secreto" explícito
	// dentro del panel, mismo criterio de siempre (minimizar cuánto tiempo
	// vive un secreto descifrado en memoria).
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import SecretField from '$lib/components/SecretField.svelte';
	import FolderTree from '$lib/components/FolderTree.svelte';
	import TagFilterBar from '$lib/components/TagFilterBar.svelte';
	import Table from '$lib/components/Table.svelte';
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
	import { passwordPolicyApi } from '$lib/api/admin';
	import { generarPassword, type ReglasCharset } from '$lib/crypto/passwordGenerator';
	import { externalSharesApi } from '$lib/api/externalShares';
	import { cifrarContenidoDeShare } from '$lib/crypto/externalShare';
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
			// (ej. el panel abierto) en un refresco por foco sin cambios reales.
			if (huboCambios(recursos, nuevos)) recursos = nuevos;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.vault.error;
		} finally {
			cargando = false;
		}
	}

	// F-15: defaults de spec/02-modelo-de-datos.md — si `GET
	// /admin/password-policy` falla, generar sigue funcionando con esto en
	// vez de romperse.
	let generatorLongitud = $state(20);
	let generatorReglas = $state<ReglasCharset>({
		uppercase: true,
		lowercase: true,
		digits: true,
		symbols: true,
		exclude_ambiguous: true
	});

	onMount(() => {
		cargar();
		cargarOrganizacion();
		passwordPolicyApi
			.obtener()
			.then((p) => {
				generatorLongitud = p.generator_default_length;
				generatorReglas = p.generator_charset_rules as ReglasCharset;
			})
			.catch(() => {
				/* default local declarado arriba sigue sirviendo */
			});
		// F-30 (07-frontend-web.md §2): recargar al volver a la pestaña, sin
		// polling — cubre el caso de compartir/crear un recurso desde otro
		// dispositivo mientras esta pestaña quedó abierta en segundo plano.
		return refrescarAlEnfocar(cargar);
	});

	function generar() {
		password = generarPassword(generatorLongitud, generatorReglas);
	}

	function generarParaEdicion() {
		editPassword = generarPassword(generatorLongitud, generatorReglas);
	}

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

	// --- panel de detalle: un solo recurso seleccionado a la vez ---
	let seleccionado = $state<Recurso | undefined>();
	let panelModo = $state<'detalle' | 'editar' | 'compartir' | 'externo'>('detalle');

	function seleccionarFila(recurso: Recurso) {
		if (seleccionado?.id === recurso.id) {
			seleccionado = undefined;
			return;
		}
		seleccionado = recurso;
		panelModo = 'detalle';
		secretoAbierto = undefined;
		errorSecreto = undefined;
		emailCompartir = '';
		errorCompartir = undefined;
		compartidoOk = false;
		externoPassphrase = '';
		externoExpiraHoras = '24';
		externoMaxVistas = '1';
		externoError = undefined;
		externoLink = undefined;
	}

	function cerrarPanel() {
		seleccionado = undefined;
	}

	// --- ver secreto ---
	let secretoAbierto = $state<{ password: string; notes: string; totpSecret?: string } | undefined>();
	let cargandoSecreto = $state(false);
	let errorSecreto = $state<string | undefined>();

	async function verSecretoDelSeleccionado() {
		if (!seleccionado || !$clavesDesbloqueadas) return;
		errorSecreto = undefined;
		cargandoSecreto = true;
		try {
			secretoAbierto = await verSecreto(seleccionado, $clavesDesbloqueadas);
		} catch (err) {
			errorSecreto = err instanceof ApiError ? err.message : $t.vault.errorVerSecreto;
		} finally {
			cargandoSecreto = false;
		}
	}

	// --- editar (F-07, ver recursos.ts::editarRecurso) ---
	let editNombre = $state('');
	let editUsuario = $state('');
	let editUri = $state('');
	let editPassword = $state('');
	let editNotas = $state('');
	let editTotp = $state('');
	let cargandoParaEditar = $state(false);
	let guardandoEdicion = $state(false);
	let errorEditar = $state<string | undefined>();

	async function empezarEditar() {
		if (!seleccionado || !$clavesDesbloqueadas) return;
		errorEditar = undefined;
		panelModo = 'editar';
		cargandoParaEditar = true;
		try {
			const secreto = await verSecreto(seleccionado, $clavesDesbloqueadas);
			editNombre = seleccionado.nombre;
			editUsuario = seleccionado.usuario;
			editUri = seleccionado.uri;
			editPassword = secreto.password;
			editNotas = secreto.notes;
			editTotp = secreto.totpSecret ?? '';
		} catch (err) {
			errorEditar = err instanceof ApiError ? err.message : $t.vault.errorVerSecreto;
		} finally {
			cargandoParaEditar = false;
		}
	}

	async function guardarEdicion(e: SubmitEvent) {
		e.preventDefault();
		if (!seleccionado || !$clavesDesbloqueadas) return;
		errorEditar = undefined;
		guardandoEdicion = true;
		try {
			const actualizado = await editarRecurso(
				seleccionado,
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
			recursos = recursos.map((r) => (r.id === seleccionado!.id ? actualizado : r));
			seleccionado = actualizado;
			panelModo = 'detalle';
		} catch (err) {
			errorEditar = err instanceof ApiError ? err.message : $t.vault.errorEditar;
		} finally {
			guardandoEdicion = false;
		}
	}

	// --- compartir ---
	let emailCompartir = $state('');
	let enviandoCompartir = $state(false);
	let errorCompartir = $state<string | undefined>();
	let compartidoOk = $state(false);

	async function enviarCompartir(e: SubmitEvent) {
		e.preventDefault();
		if (!seleccionado || !$clavesDesbloqueadas) return;
		errorCompartir = undefined;
		enviandoCompartir = true;
		try {
			await compartirRecurso(seleccionado, emailCompartir, $clavesDesbloqueadas);
			compartidoOk = true;
			emailCompartir = '';
		} catch (err) {
			errorCompartir = err instanceof ApiError ? err.message : $t.vault.errorCompartir;
		} finally {
			enviandoCompartir = false;
		}
	}

	// --- compartir externo (F-26) — comparte la contraseña del recurso con
	// alguien sin cuenta en Ellkan, vía /s/{id}. Sólo la contraseña (no
	// notas/TOTP): es el caso de uso más común y evita ambigüedad sobre qué
	// campo va en el link.
	let externoPassphrase = $state('');
	let externoExpiraHoras = $state('24');
	let externoMaxVistas = $state('1');
	let externoCreando = $state(false);
	let externoError = $state<string | undefined>();
	let externoLink = $state<string | undefined>();

	async function crearExterno(e: SubmitEvent) {
		e.preventDefault();
		if (!seleccionado || !$clavesDesbloqueadas) return;
		externoError = undefined;
		externoCreando = true;
		try {
			const secreto = await verSecreto(seleccionado, $clavesDesbloqueadas);
			const { ciphertextB64, claveFragmentoB64Url, passwordSaltB64 } = await cifrarContenidoDeShare(
				secreto.password,
				externoPassphrase || undefined
			);
			const creado = await externalSharesApi.crear({
				ciphertext_b64: ciphertextB64,
				password_protected: !!externoPassphrase,
				password_salt_b64: passwordSaltB64,
				max_views: Number(externoMaxVistas),
				expires_in_hours: Number(externoExpiraHoras)
			});
			externoLink = `${location.origin}/s/${creado.id}#${claveFragmentoB64Url}`;
		} catch (err) {
			externoError = err instanceof ApiError ? err.message : $t.vault.errorExterno;
		} finally {
			externoCreando = false;
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
	<div class="vault-layout" class:con-panel={!!seleccionado}>
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
						<div class="con-generar">
							<TextField label={$t.vault.password} type="password" bind:value={password} required />
							<Button type="button" variant="ghost" onclick={generar}>{$t.vault.generarPassword}</Button>
						</div>
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
				{:else}
					<Table
						columnas={[
							{ key: 'nombre', header: $t.vault.nombre },
							{ key: 'usuario', header: $t.vault.usuario },
							{ key: 'uri', header: $t.vault.uri },
							{ key: 'tipo', header: '' }
						]}
						filas={recursosFiltrados}
						claveFila={(r) => r.id}
						seleccionadaId={seleccionado?.id}
						onSeleccionar={seleccionarFila}
					>
						{#snippet fila(r)}
							<td>{r.nombre}</td>
							<td class="secundario">{r.usuario}</td>
							<td class="secundario">{r.uri}</td>
							<td class="secundario">
								{r.metadataKeyType === 'shared_key' ? $t.vault.compartir : $t.vault.personal}
							</td>
						{/snippet}
					</Table>
				{/if}
			{/if}
		</Card>

		{#if seleccionado}
			<Card padded={true}>
				<div class="panel">
					<div class="panel-cabecera">
						<h2>{seleccionado.nombre}</h2>
						<button type="button" class="cerrar" onclick={cerrarPanel} title={$t.vault.cerrarPanel}>&times;</button>
					</div>

					{#if panelModo === 'detalle'}
						<dl class="campos">
							<dt>{$t.vault.usuario}</dt>
							<dd>{seleccionado.usuario || '—'}</dd>
							{#if seleccionado.uri}
								<dt>{$t.vault.uri}</dt>
								<dd><a href={seleccionado.uri} target="_blank" rel="noreferrer">{seleccionado.uri}</a></dd>
							{/if}
						</dl>

						{#if !secretoAbierto}
							<Button variant="secondary" onclick={verSecretoDelSeleccionado} loading={cargandoSecreto}>
								{$t.vault.verSecreto}
							</Button>
						{:else}
							<SecretField label={$t.vault.password} valor={secretoAbierto.password} />
							{#if secretoAbierto.notes}
								<p class="notas">{secretoAbierto.notes}</p>
							{/if}
							{#if secretoAbierto.totpSecret}
								<SecretField label="TOTP" valor={secretoAbierto.totpSecret} />
							{/if}
						{/if}
						{#if errorSecreto}<p class="error">{errorSecreto}</p>{/if}

						<div class="panel-acciones">
							<Button variant="ghost" onclick={empezarEditar}>{$t.vault.editar}</Button>
							{#if seleccionado.metadataKeyType === 'shared_key'}
								<Button variant="ghost" onclick={() => (panelModo = 'compartir')}>{$t.vault.compartir}</Button>
							{/if}
							<Button variant="ghost" onclick={() => (panelModo = 'externo')}>{$t.vault.compartirExterno}</Button>
						</div>
					{:else if panelModo === 'editar'}
						{#if cargandoParaEditar}
							<p>{$t.vault.cargando}</p>
						{:else}
							<form onsubmit={guardarEdicion}>
								<TextField label={$t.vault.nombre} bind:value={editNombre} required />
								<TextField label={$t.vault.usuario} bind:value={editUsuario} />
								<TextField label={$t.vault.uri} bind:value={editUri} />
								<div class="con-generar">
									<TextField label={$t.vault.password} type="password" bind:value={editPassword} required />
									<Button type="button" variant="ghost" onclick={generarParaEdicion}>{$t.vault.generarPassword}</Button>
								</div>
								<TextField label={$t.vault.notas} bind:value={editNotas} />
								<TextField label={$t.vault.totpOpcional} bind:value={editTotp} />
								{#if errorEditar}<p class="error">{errorEditar}</p>{/if}
								<div class="botones">
									<Button type="submit" variant="primary" loading={guardandoEdicion}>{$t.vault.guardarEdicion}</Button>
									<Button type="button" variant="ghost" onclick={() => (panelModo = 'detalle')}>{$t.vault.cancelar}</Button>
								</div>
							</form>
						{/if}
					{:else if panelModo === 'compartir'}
						<form onsubmit={enviarCompartir}>
							<TextField label={$t.vault.compartirCon} type="email" bind:value={emailCompartir} required />
							{#if errorCompartir}<p class="error">{errorCompartir}</p>{/if}
							{#if compartidoOk}<p class="ok">{$t.vault.compartido}</p>{/if}
							<div class="botones">
								<Button type="submit" variant="primary" loading={enviandoCompartir}>{$t.vault.enviarCompartir}</Button>
								<Button type="button" variant="ghost" onclick={() => (panelModo = 'detalle')}>{$t.vault.cancelar}</Button>
							</div>
						</form>
					{:else if panelModo === 'externo'}
						<form onsubmit={crearExterno}>
							<TextField label={$t.vault.externoExpiraHoras} type="number" bind:value={externoExpiraHoras} required />
							<TextField label={$t.vault.externoMaxVistas} type="number" bind:value={externoMaxVistas} required />
							<TextField label={$t.vault.externoPassphrase} type="password" bind:value={externoPassphrase} />
							{#if externoError}<p class="error">{externoError}</p>{/if}
							{#if externoLink}
								<p class="hint">{$t.vault.externoLinkListo}</p>
								<SecretField label={$t.vault.compartirExterno} valor={externoLink} />
								<Button type="button" variant="ghost" onclick={() => (panelModo = 'detalle')}>{$t.vault.cancelar}</Button>
							{:else}
								<div class="botones">
									<Button type="submit" variant="primary" loading={externoCreando}>{$t.vault.externoCrear}</Button>
									<Button type="button" variant="ghost" onclick={() => (panelModo = 'detalle')}>{$t.vault.cancelar}</Button>
								</div>
							{/if}
						</form>
					{/if}
				</div>
			</Card>
		{/if}
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
	.vault-layout.con-panel {
		grid-template-columns: 14rem 1fr 22rem;
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
	form.crear {
		display: flex;
		flex-direction: column;
		max-width: 24rem;
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-4);
		margin-bottom: var(--space-4);
	}
	.con-generar {
		display: flex;
		align-items: flex-end;
		gap: var(--space-2);
	}
	.con-generar :global(.field) {
		flex: 1;
		margin-bottom: 0;
	}
	.botones {
		display: flex;
		gap: var(--space-2);
	}
	:global(.secundario) {
		color: var(--text-muted);
	}
	.panel {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
	.panel form {
		display: flex;
		flex-direction: column;
		gap: 0;
	}
	.panel-cabecera {
		display: flex;
		align-items: flex-start;
		justify-content: space-between;
		gap: var(--space-2);
	}
	.panel-cabecera h2 {
		margin: 0;
		font-size: var(--text-lg);
		color: var(--text-primary);
		word-break: break-word;
	}
	.cerrar {
		background: none;
		border: none;
		color: var(--text-muted);
		font-size: var(--text-xl);
		line-height: 1;
		cursor: pointer;
		flex-shrink: 0;
	}
	.cerrar:hover {
		color: var(--text-primary);
	}
	.campos {
		margin: 0;
		font-size: var(--text-sm);
	}
	.campos dt {
		color: var(--text-muted);
		margin-top: var(--space-2);
	}
	.campos dd {
		margin: 0;
		color: var(--text-primary);
		word-break: break-word;
	}
	.panel-acciones {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
		border-top: 1px solid var(--border-color);
		padding-top: var(--space-3);
	}
	.notas {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		white-space: pre-wrap;
	}
</style>
