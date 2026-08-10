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
	import { copiarConLimpieza } from '$lib/clipboard';
	import { exportPolicyApi, adminExportPolicyApi, type ExportPolicy } from '$lib/api/exportPolicy';
	import {
		construirFilasExport,
		exportar,
		descargarArchivo,
		parsearArchivoImport,
		importar,
		detectarFormatoPorNombre,
		type FormatoExport,
		type FilaExport
	} from '$lib/crypto/exportImport';
	import { evaluarFortaleza } from '$lib/crypto/passwordStrength';
	import { sesion, clavesDesbloqueadas, preferencias } from '$lib/state/session';
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

	// Copiar usuario/URI del panel de detalle — no son secretos, pero
	// respetan el mismo timer de limpieza automática que el resto de la app
	// (`preferencias.clipboardClearMinutes`), mismo criterio que `SecretField`.
	let campoCopiado = $state<'usuario' | 'uri' | undefined>();
	async function copiarCampo(campo: 'usuario' | 'uri', valor: string) {
		await copiarConLimpieza(valor, $preferencias.clipboardClearMinutes);
		campoCopiado = campo;
		setTimeout(() => (campoCopiado = undefined), 2000);
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

	// --- selección masiva (F-27, export selectivo) — mismo patrón que
	// `(app)/admin/users/+page.svelte` ---
	let seleccionados = $state<Set<string>>(new Set());
	function toggleSeleccion(id: string) {
		const nuevo = new Set(seleccionados);
		if (nuevo.has(id)) nuevo.delete(id);
		else nuevo.add(id);
		seleccionados = nuevo;
	}
	function toggleSeleccionTodos() {
		seleccionados =
			seleccionados.size === recursosFiltrados.length ? new Set() : new Set(recursosFiltrados.map((r) => r.id));
	}

	// --- exportar/importar (F-27) — antes vivía en `/settings/export-import`,
	// separado del propio Vault que exporta; movido acá para poder elegir
	// "todos" o sólo lo seleccionado arriba, sin duplicar la carga/descifrado
	// de recursos que `cargar()` ya hizo.
	let mostrarExportar = $state(false);
	let cargandoPolitica = $state(true);
	let politica = $state<ExportPolicy | undefined>();
	let excepcionAdmin = $state(false);

	async function abrirExportar() {
		mostrarExportar = !mostrarExportar;
		if (!mostrarExportar || politica) return;
		cargandoPolitica = true;
		try {
			politica = await exportPolicyApi.obtener();
		} catch {
			/* sin política, el panel queda oculto (puedeExportar/puedeImportar dan false) */
		}
		if (politica && !politica.export_enabled) {
			try {
				await adminExportPolicyApi.obtener();
				excepcionAdmin = true;
			} catch {
				excepcionAdmin = false;
			}
		}
		cargandoPolitica = false;
	}

	const puedeExportar = $derived(!!politica && (politica.export_enabled || excepcionAdmin));
	const puedeImportar = $derived(!!politica && politica.import_enabled);
	const formatosDisponibles = $derived((politica?.allowed_formats ?? []) as FormatoExport[]);

	let alcanceExport = $state<'todos' | 'seleccionados'>('todos');
	let formatoExport = $state<FormatoExport>('kdbx');
	let passwordExport = $state('');
	let exportando = $state(false);
	let errorExport = $state<string | undefined>();
	let okExport = $state<number | undefined>();
	const fortalezaExport = $derived(evaluarFortaleza(passwordExport));
	const labelFortalezaExport = $derived(
		[
			$t.fortalezaPassword.muyDebil,
			$t.fortalezaPassword.debil,
			$t.fortalezaPassword.aceptable,
			$t.fortalezaPassword.fuerte,
			$t.fortalezaPassword.muyFuerte
		][fortalezaExport.score]
	);

	async function hacerExport(e: SubmitEvent) {
		e.preventDefault();
		if (!$clavesDesbloqueadas) return;
		errorExport = undefined;
		okExport = undefined;
		exportando = true;
		try {
			const aExportar =
				alcanceExport === 'seleccionados' ? recursos.filter((r) => seleccionados.has(r.id)) : recursos;
			const { filas } = await construirFilasExport(aExportar, $clavesDesbloqueadas);
			const archivo = await exportar(formatoExport, filas, {
				password: formatoExport === 'kdbx' ? passwordExport : undefined,
				cuentaEmail: $sesion.email ?? ''
			});
			descargarArchivo(archivo);
			okExport = filas.length;
			passwordExport = '';
		} catch (err) {
			errorExport = err instanceof ApiError ? err.message : err instanceof Error ? err.message : $t.exportImport.errorExportar;
		} finally {
			exportando = false;
		}
	}

	let archivoImport = $state<File | undefined>();
	let passwordImport = $state('');
	let filasPreview = $state<FilaExport[] | undefined>();
	let previsualizando = $state(false);
	let importando = $state(false);
	let errorImport = $state<string | undefined>();
	let okImport = $state<number | undefined>();

	function alElegirArchivo(e: Event) {
		archivoImport = (e.target as HTMLInputElement).files?.[0];
		filasPreview = undefined;
		errorImport = undefined;
		okImport = undefined;
	}

	async function previsualizar() {
		if (!archivoImport) return;
		errorImport = undefined;
		okImport = undefined;
		const formato = detectarFormatoPorNombre(archivoImport.name);
		if (!formato) {
			errorImport = $t.exportImport.errorFormatoDesconocido;
			return;
		}
		previsualizando = true;
		try {
			const bytes = await archivoImport.arrayBuffer();
			filasPreview = await parsearArchivoImport(formato, bytes, {
				password: formato === 'kdbx' ? passwordImport : undefined
			});
		} catch (err) {
			errorImport = err instanceof ApiError ? err.message : err instanceof Error ? err.message : $t.exportImport.errorImportar;
			filasPreview = undefined;
		} finally {
			previsualizando = false;
		}
	}

	async function confirmarImport() {
		if (!filasPreview || !archivoImport || !$clavesDesbloqueadas || !$sesion.userId) return;
		const formato = detectarFormatoPorNombre(archivoImport.name);
		if (!formato) return;
		errorImport = undefined;
		importando = true;
		try {
			const creados = await importar(formato, filasPreview, $clavesDesbloqueadas, $sesion.userId);
			okImport = creados;
			filasPreview = undefined;
			archivoImport = undefined;
			passwordImport = '';
			await cargar();
		} catch (err) {
			errorImport = err instanceof ApiError ? err.message : err instanceof Error ? err.message : $t.exportImport.errorImportar;
		} finally {
			importando = false;
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
					<div class="botones">
						<Button variant="secondary" onclick={abrirExportar}>{$t.exportImport.titulo}</Button>
						<Button variant="primary" onclick={() => (mostrarCrear = !mostrarCrear)}>{$t.vault.nuevoRecurso}</Button>
					</div>
				</div>

				{#if mostrarExportar}
					<div class="panel-exportar">
						{#if cargandoPolitica}
							<p class="hint">{$t.exportImport.cargandoPolitica}</p>
						{:else if !puedeExportar && !puedeImportar}
							<p class="hint">{$t.exportImport.sinFormatosHabilitados}</p>
						{:else}
							{#if politica && !politica.export_enabled && excepcionAdmin}
								<p class="hint">{$t.exportImport.viaExcepcionAdmin}</p>
							{/if}

							{#if puedeExportar}
								<h3>{$t.exportImport.exportarTitulo}</h3>
								<p class="hint">{$t.exportImport.exportarHint}</p>
								<form onsubmit={hacerExport}>
									<div class="field">
										<label for="alcance-export">{$t.exportImport.alcance}</label>
										<select id="alcance-export" bind:value={alcanceExport}>
											<option value="todos">{$t.exportImport.alcanceTodos(recursosFiltrados.length)}</option>
											<option value="seleccionados" disabled={seleccionados.size === 0}>
												{$t.exportImport.alcanceSeleccionados(seleccionados.size)}
											</option>
										</select>
									</div>
									<div class="field">
										<label for="formato-export">{$t.exportImport.formato}</label>
										<select id="formato-export" bind:value={formatoExport}>
											{#each formatosDisponibles as f (f)}
												<option value={f}>{f.toUpperCase()}</option>
											{/each}
										</select>
									</div>
									{#if formatoExport === 'kdbx'}
										<TextField
											label={$t.exportImport.passwordArchivo}
											type="password"
											bind:value={passwordExport}
											hint={$t.exportImport.passwordArchivoHint}
											required
										/>
										{#if passwordExport}
											<p class="fortaleza fortaleza-{fortalezaExport.score}">{labelFortalezaExport}</p>
										{/if}
									{/if}
									{#if errorExport}<p class="error">{errorExport}</p>{/if}
									{#if okExport !== undefined}<p class="ok">{$t.exportImport.exportadoOk(okExport)}</p>{/if}
									<Button type="submit" variant="primary" loading={exportando}>{$t.exportImport.exportar}</Button>
								</form>
							{/if}

							{#if puedeImportar}
								<h3>{$t.exportImport.importarTitulo}</h3>
								<p class="hint">{$t.exportImport.importarHint}</p>
								<div class="field">
									<label for="archivo-import">{$t.exportImport.archivo}</label>
									<input id="archivo-import" type="file" accept=".kdbx,.csv,.json" onchange={alElegirArchivo} />
								</div>
								{#if archivoImport && detectarFormatoPorNombre(archivoImport.name) === 'kdbx'}
									<TextField label={$t.exportImport.passwordArchivoImport} type="password" bind:value={passwordImport} />
								{/if}
								{#if errorImport}<p class="error">{errorImport}</p>{/if}
								{#if !filasPreview}
									<Button variant="secondary" onclick={previsualizar} disabled={!archivoImport} loading={previsualizando}>
										{$t.exportImport.previsualizar}
									</Button>
								{:else}
									<p class="hint">{$t.exportImport.previewConteo(filasPreview.length)}</p>
									<Button variant="primary" onclick={confirmarImport} loading={importando}>
										{$t.exportImport.confirmarImportar}
									</Button>
								{/if}
								{#if okImport !== undefined}<p class="ok">{$t.exportImport.importadoOk(okImport)}</p>{/if}
							{/if}
						{/if}
					</div>
				{/if}

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
					<div class="barra-seleccion">
						<button type="button" class="link" onclick={toggleSeleccionTodos}>
							{seleccionados.size === recursosFiltrados.length && recursosFiltrados.length > 0
								? $t.vault.deseleccionarTodos
								: $t.vault.seleccionarTodos}
						</button>
						{#if seleccionados.size > 0}<span class="hint">{$t.vault.conteoSeleccionados(seleccionados.size)}</span>{/if}
					</div>
					<Table
						columnas={[
							{ key: 'sel', header: '' },
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
							<td onclick={(e) => e.stopPropagation()}>
								<input type="checkbox" checked={seleccionados.has(r.id)} onchange={() => toggleSeleccion(r.id)} />
							</td>
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
							<dd>
								{seleccionado.usuario || '—'}
								{#if seleccionado.usuario}
									<button
										type="button"
										class="icono-copiar"
										onclick={() => copiarCampo('usuario', seleccionado!.usuario)}
										aria-label={$t.secretField.copiar}
									>
										{campoCopiado === 'usuario' ? '✓' : '⧉'}
									</button>
								{/if}
							</dd>
							{#if seleccionado.uri}
								<dt>{$t.vault.uri}</dt>
								<dd>
									<a href={seleccionado.uri} target="_blank" rel="noreferrer">{seleccionado.uri}</a>
									<button
										type="button"
										class="icono-copiar"
										onclick={() => copiarCampo('uri', seleccionado!.uri)}
										aria-label={$t.secretField.copiar}
									>
										{campoCopiado === 'uri' ? '✓' : '⧉'}
									</button>
								</dd>
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
	.icono-copiar {
		background: none;
		border: none;
		cursor: pointer;
		font-size: var(--text-sm);
		line-height: 1;
		padding: 0 0 0 var(--space-1);
		color: var(--text-secondary);
		vertical-align: middle;
	}
	.icono-copiar:hover {
		color: var(--text-primary);
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
	h3 {
		margin: 0 0 var(--space-1) 0;
		font-size: var(--text-base);
		color: var(--text-primary);
	}
	.panel-exportar {
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-4);
		margin-bottom: var(--space-4);
	}
	.panel-exportar form {
		display: flex;
		flex-direction: column;
		max-width: 24rem;
		margin-bottom: var(--space-4);
	}
	.panel-exportar .field {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		margin-bottom: var(--space-4);
	}
	.panel-exportar label {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		font-weight: 500;
	}
	.panel-exportar select,
	.panel-exportar input[type='file'] {
		background: var(--bg-raised);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
		color: var(--text-primary);
	}
	.fortaleza {
		font-size: var(--text-xs);
		margin: calc(-1 * var(--space-3)) 0 var(--space-4) 0;
	}
	.fortaleza-0,
	.fortaleza-1 {
		color: var(--danger);
	}
	.fortaleza-2 {
		color: var(--warning);
	}
	.fortaleza-3,
	.fortaleza-4 {
		color: var(--success);
	}
	.barra-seleccion {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		margin-bottom: var(--space-2);
	}
	.barra-seleccion .link {
		background: none;
		border: none;
		padding: 0;
		font-size: var(--text-xs);
		color: var(--accent-primary);
		cursor: pointer;
	}
</style>
