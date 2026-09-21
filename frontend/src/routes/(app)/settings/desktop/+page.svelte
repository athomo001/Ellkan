<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-45 (spec/13 §3): paso que hasta el 2026-09-17 no existía — el
	// usuario nunca podía ver ni elegir el puerto fijo del backend local,
	// sólo heredaba el que `bindear_puerto` autoeligió en el primer
	// arranque. `$lib/tauri/puerto.ts` es el wrapper de los comandos Tauri.
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import { t } from '$lib/i18n';
	import { puertoActual, puertoConfigurado, configurarPuertoFijo, infoApp, type InfoApp } from '$lib/tauri/puerto';
	import { alCerrarConfigurado, configurarAlCerrar, type AlCerrar } from '$lib/tauri/ventana';
	import {
		estadoSistema,
		configurarAutostart,
		configurarEnlaces,
		configurarBloqueoPantalla,
		type EstadoSistema,
		type Respaldos
	} from '$lib/tauri/sistema';
	import { api } from '$lib/api/client';

	// Qué hace la "X" de la ventana: preguntar / bandeja / cerrar del todo.
	let alCerrar = $state<AlCerrar>('preguntar');
	let errorCierre = $state<string | undefined>();

	$effect(() => {
		alCerrarConfigurado()
			.then((m) => (alCerrar = m))
			.catch(() => {});
	});

	async function elegirAlCerrar(modo: AlCerrar) {
		errorCierre = undefined;
		try {
			await configurarAlCerrar(modo);
			alCerrar = modo;
		} catch (err) {
			errorCierre = typeof err === 'string' ? err : $t.settingsDesktop.alCerrarError;
		}
	}

	// Inicio con la sesión, enlaces ellkan://, bloqueo con la pantalla y modo
	// portable (Windows). La lógica vive en el shell; acá sólo se muestran y
	// se cambian.
	let sistema = $state<EstadoSistema | undefined>();
	let errorSistema = $state<string | undefined>();

	$effect(() => {
		estadoSistema()
			.then((e) => (sistema = e))
			.catch(() => {});
	});

	async function cambiarSistema(cambio: () => Promise<void>) {
		errorSistema = undefined;
		try {
			await cambio();
			sistema = await estadoSistema();
		} catch (err) {
			errorSistema = typeof err === 'string' ? err : $t.settingsDesktop.sistemaError;
			sistema = await estadoSistema().catch(() => sistema);
		}
	}

	// Copias de seguridad de la bóveda (F-53).
	let respaldos = $state<Respaldos | undefined>();
	let creandoRespaldo = $state(false);
	let errorRespaldo = $state<string | undefined>();
	let respaldoCreado = $state(false);

	$effect(() => {
		api.get<Respaldos>('/vault/backups')
			.then((r) => (respaldos = r))
			.catch(() => {});
	});

	async function crearRespaldoAhora() {
		errorRespaldo = undefined;
		respaldoCreado = false;
		creandoRespaldo = true;
		try {
			respaldos = await api.post<Respaldos>('/vault/backups');
			respaldoCreado = true;
		} catch (err) {
			errorRespaldo = err instanceof Error ? err.message : $t.settingsDesktop.respaldosError;
		} finally {
			creandoRespaldo = false;
		}
	}

	async function mostrarCarpetaDeRespaldos() {
		if (!respaldos) return;
		try {
			const { revealItemInDir } = await import('@tauri-apps/plugin-opener');
			await revealItemInDir(respaldos.carpeta);
		} catch {
			/* sin el explorador no hay nada más que hacer: la ruta está a la vista */
		}
	}

	const formatoTamano = (bytes: number) => (bytes < 1024 * 1024 ? `${Math.max(1, Math.round(bytes / 1024))} KB` : `${(bytes / 1024 / 1024).toFixed(1)} MB`);
	import {
		estadoExtension,
		instalarExtension,
		abrirNavegadorEnExtensiones,
		dejarDeActualizarExtension,
		mostrarCarpetaExtension,
		rutaDelManifest,
		NAVEGADORES_UI,
		type EstadoExtension,
		type NavegadorExtension
	} from '$lib/tauri/extension';

	// Punto 9: extensión de navegador instalada desde la app. La extensión
	// viaja dentro del ejecutable; acá el usuario elige el navegador y la app
	// la deja en una carpeta fija que mantiene al día en cada arranque.
	//
	// Ningún navegador deja que otra aplicación instale una extensión por su
	// cuenta (sin publicarla en su tienda), así que el último paso lo confirma
	// el usuario. Lo que sí se hace solo: extraer la extensión, copiar la ruta
	// al portapapeles y abrir el navegador directamente en su página de
	// extensiones — para que sólo queden "Modo de desarrollador → Cargar
	// descomprimida → pegar".
	let extension = $state<EstadoExtension | undefined>();
	let instalando = $state<string | null>(null);
	let errorExtension = $state<string | undefined>();
	let avisoExtension = $state<string | undefined>();
	let guiaDe = $state<string | null>(null);
	let rutaCopiada = $state(false);

	async function cargarExtension() {
		try {
			extension = await estadoExtension();
		} catch (err) {
			errorExtension = typeof err === 'string' ? err : $t.settingsDesktop.extensionErrorGenerico;
		}
	}

	$effect(() => {
		cargarExtension();
	});

	function datosDe(id: string): NavegadorExtension | undefined {
		return extension?.navegadores.find((n) => n.id === id);
	}

	/** Sólo los navegadores que están de verdad instalados en esta PC. */
	const disponibles = $derived(NAVEGADORES_UI.filter((n) => datosDe(n.id)?.instalado));

	async function instalar(id: string) {
		errorExtension = undefined;
		avisoExtension = undefined;
		rutaCopiada = false;
		instalando = id;
		try {
			const datos = await instalarExtension(id);
			await cargarExtension();
			guiaDe = id;

			// Lo que el usuario tiene que elegir en el diálogo del navegador:
			// la carpeta (Chromium) o el `manifest.json` (Firefox). Se copia
			// ANTES de abrir el navegador, que se lleva el foco.
			try {
				await navigator.clipboard.writeText(id === 'firefox' ? rutaDelManifest(datos.ruta) : datos.ruta);
				rutaCopiada = true;
			} catch {
				rutaCopiada = false;
			}

			try {
				await abrirNavegadorEnExtensiones(id);
			} catch {
				const pagina = NAVEGADORES_UI.find((n) => n.id === id)?.paginaExtensiones ?? '';
				avisoExtension = $t.settingsDesktop.extensionNoAbrio.replace('{{pagina}}', pagina);
			}
		} catch (err) {
			errorExtension = typeof err === 'string' ? err : err instanceof Error ? err.message : $t.settingsDesktop.extensionErrorGenerico;
		} finally {
			instalando = null;
		}
	}

	async function dejarDeActualizar(id: string) {
		errorExtension = undefined;
		try {
			await dejarDeActualizarExtension(id);
			if (guiaDe === id) guiaDe = null;
			await cargarExtension();
		} catch (err) {
			errorExtension = typeof err === 'string' ? err : $t.settingsDesktop.extensionErrorGenerico;
		}
	}

	async function mostrarCarpeta(ruta: string) {
		errorExtension = undefined;
		try {
			await mostrarCarpetaExtension(ruta);
		} catch (err) {
			errorExtension = typeof err === 'string' ? err : $t.settingsDesktop.extensionErrorGenerico;
		}
	}

	let actual = $state<number | undefined>();
	let configurado = $state<number | null | undefined>();
	let nuevoPuerto = $state('');
	let guardando = $state(false);
	let error = $state<string | undefined>();
	let advertencia = $state<string | undefined>();
	let guardadoOk = $state(false);

	let info = $state<InfoApp | undefined>();

	$effect(() => {
		puertoActual().then((p) => (actual = p));
		puertoConfigurado().then((p) => (configurado = p));
		infoApp()
			.then((i) => (info = i))
			.catch(() => {});
	});

	/** Fecha y hora del binario en ejecución, en la hora local del usuario. */
	const fechaBinario = $derived(info?.binario_unix ? new Date(info.binario_unix * 1000).toLocaleString() : '…');

	async function guardar(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;
		advertencia = undefined;
		guardadoOk = false;
		const puerto = Number(nuevoPuerto);
		if (!Number.isInteger(puerto) || puerto < 1 || puerto > 65535) {
			error = $t.settingsDesktop.errorGenerico;
			return;
		}
		guardando = true;
		try {
			const resultado = await configurarPuertoFijo(puerto);
			advertencia = resultado.advertencia ?? undefined;
			configurado = puerto;
			guardadoOk = true;
			nuevoPuerto = '';
		} catch (err) {
			error = err instanceof Error ? err.message : $t.settingsDesktop.errorGenerico;
		} finally {
			guardando = false;
		}
	}
</script>

<svelte:head>
	<title>{$t.settingsDesktop.navTitulo} — Ellkan</title>
</svelte:head>

<div class="pila">
<Card>
	<h2>{$t.settingsDesktop.alCerrarTitulo}</h2>
	<p class="hint">{$t.settingsDesktop.alCerrarHint}</p>
	{#each [['preguntar', $t.settingsDesktop.alCerrarPreguntar], ['bandeja', $t.settingsDesktop.alCerrarBandeja], ['salir', $t.settingsDesktop.alCerrarSalir]] as [valor, etiqueta] (valor)}
		<label class="opcion-cierre">
			<input type="radio" name="al-cerrar" value={valor} checked={alCerrar === valor} onchange={() => elegirAlCerrar(valor as AlCerrar)} />
			{etiqueta}
		</label>
	{/each}
	{#if errorCierre}<p class="error">{errorCierre}</p>{/if}
</Card>

<Card>
	<h2>{$t.settingsDesktop.sistemaTitulo}</h2>
	{#if sistema && !sistema.soportado}
		<p class="hint">{$t.settingsDesktop.sistemaNoSoportado}</p>
	{:else if sistema}
		<label class="opcion-cierre">
			<input
				type="checkbox"
				id="opcion-autostart"
				checked={sistema.autostart}
				onchange={(e) => cambiarSistema(() => configurarAutostart(e.currentTarget.checked))}
			/>
			{$t.settingsDesktop.autostartEtiqueta}
		</label>
		<p class="hint">{$t.settingsDesktop.autostartHint}</p>

		<label class="opcion-cierre">
			<input
				type="checkbox"
				id="opcion-enlaces"
				checked={sistema.enlaces}
				onchange={(e) => cambiarSistema(() => configurarEnlaces(e.currentTarget.checked))}
			/>
			{$t.settingsDesktop.enlacesEtiqueta}
		</label>
		<p class="hint">{$t.settingsDesktop.enlacesHint}</p>

		<label class="opcion-cierre">
			<input
				type="checkbox"
				id="opcion-bloqueo-pantalla"
				checked={sistema.bloquear_con_pantalla}
				onchange={(e) => cambiarSistema(() => configurarBloqueoPantalla(e.currentTarget.checked))}
			/>
			{$t.settingsDesktop.bloqueoPantallaEtiqueta}
		</label>
		<p class="hint">{$t.settingsDesktop.bloqueoPantallaHint}</p>

		{#if sistema.portable}
			<p class="ok">{$t.settingsDesktop.portableAviso.replace('{{ruta}}', sistema.carpeta_de_datos)}</p>
		{/if}
	{/if}
	{#if errorSistema}<p class="error">{errorSistema}</p>{/if}
</Card>

<Card>
	<h2>{$t.settingsDesktop.respaldosTitulo}</h2>
	<p class="hint">{$t.settingsDesktop.respaldosHint}</p>

	{#if respaldos}
		{#if respaldos.respaldos.length === 0}
			<p class="hint">{$t.settingsDesktop.respaldosNinguna}</p>
		{:else}
			<ul class="respaldos">
				{#each respaldos.respaldos as r (r.nombre)}
					<li>
						{new Date(r.creado_unix * 1000).toLocaleString()} — {formatoTamano(r.bytes)} —
						{r.automatico ? $t.settingsDesktop.respaldosAutomatica : $t.settingsDesktop.respaldosManual}
					</li>
				{/each}
			</ul>
		{/if}
		<p class="hint"><code>{respaldos.carpeta}</code></p>
	{/if}

	<div class="acciones">
		<Button variant="primary" onclick={crearRespaldoAhora} loading={creandoRespaldo}>{$t.settingsDesktop.respaldosCrear}</Button>
		<Button onclick={mostrarCarpetaDeRespaldos}>{$t.settingsDesktop.respaldosMostrar}</Button>
	</div>
	{#if respaldoCreado}<p class="ok">{$t.settingsDesktop.respaldosCreada}</p>{/if}
	{#if errorRespaldo}<p class="error">{errorRespaldo}</p>{/if}
</Card>

<Card>
	<h2>{$t.settingsDesktop.titulo}</h2>
	<p class="hint">{$t.settingsDesktop.hint}</p>

	<dl>
		<dt>{$t.settingsDesktop.versionApp}</dt>
		<dd>{info?.version ?? '…'} — {$t.settingsDesktop.binarioDel} {fechaBinario}</dd>
		<dt>{$t.settingsDesktop.puertoActual}</dt>
		<dd>{actual ?? '…'}</dd>
		<dt>{$t.settingsDesktop.puertoConfigurado}</dt>
		<dd>{configurado ?? $t.settingsDesktop.puertoSinConfigurar}</dd>
	</dl>

	<form onsubmit={guardar}>
		<TextField
			label={$t.settingsDesktop.nuevoPuerto}
			type="number"
			bind:value={nuevoPuerto}
			placeholder="49152"
			required
		/>
		{#if error}<p class="error">{error}</p>{/if}
		{#if advertencia}<p class="warning">{advertencia}</p>{/if}
		{#if guardadoOk}<p class="ok">{$t.settingsDesktop.hintAplicaProximoArranque}</p>{/if}
		<Button type="submit" variant="primary" loading={guardando}>{$t.settingsDesktop.guardar}</Button>
	</form>
</Card>

<Card>
	<h2>{$t.settingsDesktop.extensionTitulo}</h2>
	<p class="hint">{$t.settingsDesktop.extensionHint}</p>

	{#if extension && !extension.incluida}
		<p class="warning">{$t.settingsDesktop.extensionSinBundle}</p>
	{:else if extension}
		<p class="hint">
			{$t.settingsDesktop.extensionVersionIncluida.replace('{{version}}', extension.version_incluida ?? '?')}
		</p>

		{#if disponibles.length === 0}
			<p class="warning">{$t.settingsDesktop.extensionNoHayNavegadores}</p>
		{/if}

		<ul class="navegadores">
			{#each disponibles as nav (nav.id)}
				{@const datos = datosDe(nav.id)}
				<li>
					<div class="fila">
						<strong>{nav.nombre}</strong>
						{#if datos?.elegido && datos.al_dia}
							<span class="estado-ok">{$t.settingsDesktop.extensionAlDia.replace('{{version}}', datos.version_instalada ?? '?')}</span>
						{:else if datos?.elegido}
							<span class="estado-aviso">{$t.settingsDesktop.extensionDesactualizada}</span>
						{/if}
					</div>

					<div class="acciones">
						<Button variant="primary" onclick={() => instalar(nav.id)} loading={instalando === nav.id}>
							{datos?.elegido
								? $t.settingsDesktop.extensionReabrir.replace('{{navegador}}', nav.nombre)
								: $t.settingsDesktop.extensionInstalarEn.replace('{{navegador}}', nav.nombre)}
						</Button>
						{#if datos?.elegido}
							<Button onclick={() => mostrarCarpeta(datos.ruta)}>{$t.settingsDesktop.extensionMostrarCarpeta}</Button>
							<Button onclick={() => dejarDeActualizar(nav.id)}>{$t.settingsDesktop.extensionDejar}</Button>
						{/if}
					</div>

					{#if datos?.elegido && guiaDe === nav.id}
						<div class="pasos">
							{#if rutaCopiada}
								<p class="estado-ok">{$t.settingsDesktop.extensionRutaCopiada}</p>
							{/if}
							<p>
								{(nav.id === 'firefox' ? $t.settingsDesktop.extensionPasosFirefox : $t.settingsDesktop.extensionPasosChromium)
									.replace('{{navegador}}', nav.nombre)
									.replace('{{ruta}}', nav.id === 'firefox' ? rutaDelManifest(datos.ruta) : datos.ruta)}
							</p>
							{#if actual}
								<p class="estado-ok">{$t.settingsDesktop.extensionServidorListo.replace('{{url}}', `http://127.0.0.1:${actual}`)}</p>
							{/if}
						</div>
					{/if}
				</li>
			{/each}
		</ul>

		<p class="hint nota">{$t.settingsDesktop.extensionPorQueManual}</p>
	{/if}

	{#if avisoExtension}<p class="warning">{avisoExtension}</p>{/if}
	{#if errorExtension}<p class="error">{errorExtension}</p>{/if}
</Card>
</div>

<style>
	.pila {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
	}
	.opcion-cierre {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-sm);
		color: var(--text-primary);
		margin: var(--space-2) 0;
	}
	.hint {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-4) 0;
	}
	dl {
		display: grid;
		grid-template-columns: auto 1fr;
		gap: var(--space-2) var(--space-4);
		margin: 0 0 var(--space-5) 0;
		font-size: var(--text-sm);
	}
	dt {
		color: var(--text-secondary);
	}
	dd {
		margin: 0;
		color: var(--text-primary);
	}
	.ok {
		color: var(--success);
		font-size: var(--text-sm);
		margin: var(--space-2) 0;
	}
	.warning {
		color: var(--warning);
		font-size: var(--text-sm);
		margin: var(--space-2) 0;
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
		margin: var(--space-2) 0;
	}
	form {
		display: flex;
		flex-direction: column;
		max-width: 16rem;
	}
	.navegadores {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
	}
	.navegadores li {
		padding-bottom: var(--space-4);
		border-bottom: 1px solid var(--border-color);
	}
	.navegadores li:last-child {
		border-bottom: none;
		padding-bottom: 0;
	}
	.fila {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		margin-bottom: var(--space-2);
		font-size: var(--text-sm);
	}
	.acciones {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
	}
	.pasos {
		margin-top: var(--space-3);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		white-space: pre-line;
		word-break: break-word;
	}
	.pasos p {
		margin: 0 0 var(--space-2) 0;
	}
	.estado-ok {
		color: var(--success);
	}
	.estado-aviso {
		color: var(--warning);
	}
	.nota {
		margin: var(--space-4) 0 0 0;
	}
	.respaldos {
		list-style: none;
		margin: 0 0 var(--space-3) 0;
		padding: 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.respaldos li {
		padding: var(--space-1) 0;
	}
	code {
		word-break: break-all;
	}
</style>
