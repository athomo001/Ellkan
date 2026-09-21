<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-47: "modo conectado" por bóveda — vincular a un servidor Ellkan
	// remoto (equipo), opt-in, nunca automático. Sólo el camino feliz de
	// login/registro remoto (sin MFA/verificación de dispositivo del otro
	// lado, ver `$lib/sync/vinculacion.ts`).
	import { get } from 'svelte/store';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import { t } from '$lib/i18n';
	import { sesion, clavesDesbloqueadas } from '$lib/state/session';
	import {
		obtenerVinculacion,
		desvincular,
		reiniciarCursor,
		vincularConCuentaExistente,
		vincularComoBovedaNueva,
		diagnosticarCuentaRemota,
		ErrorCuentaRemota,
		type DiagnosticoFallido
	} from '$lib/sync/vinculacion';
	import { sincronizarAhora, type ResultadoSync } from '$lib/sync/motor';
	import { estadoSync } from '$lib/sync/notificador';
	import { obtenerPersistencia, cambiarPersistencia, type ModoPersistencia } from '$lib/sync/persistencia';
	import { cambiarEmailLocal, CambioEmailBloqueado, CambioEmailNoAplica } from '$lib/sync/cuentaLocal';
	import { servidorAlcanzable, type EstadoConexion } from '$lib/sync/conectividad';
	import { verificarTraspaso } from '$lib/sync/diagnostico';
	import type { InformeTraspaso } from '$lib/sync/traspaso';
	import { ApiError } from '$lib/api/client';

	const email = $derived($sesion.email ?? '');
	let vinculacion = $state<ReturnType<typeof obtenerVinculacion>>(null);
	$effect(() => {
		vinculacion = email ? obtenerVinculacion(email) : null;
	});

	let modo = $state<'existente' | 'nueva'>('existente');
	let serverUrl = $state('');
	let displayName = $state('');
	let vinculando = $state(false);
	let errorVinculacion = $state<string | undefined>();
	// Cuando el servidor no aceptó la cuenta, la causa más común es que el
	// correo local no es el de la cuenta de allá — se sugiere cambiarlo.
	let sugerirCambiarCorreo = $state(false);

	/** Texto traducido de un diagnóstico de `diagnosticarCuentaRemota`. */
	function textoDiagnostico(d: DiagnosticoFallido): string {
		switch (d.estado) {
			case 'sin_conexion':
				return $t.settingsSync.diagSinConexion;
			case 'servidor_invalido':
				return $t.settingsSync.diagServidorInvalido;
			case 'no_autenticado':
				return $t.settingsSync.diagNoAutenticado;
			case 'requiere_paso_extra':
				return $t.settingsSync.diagPasoExtra.replace('{{paso}}', d.paso);
			case 'error':
				return d.mensaje;
		}
	}

	function textoDeError(err: unknown, porDefecto: string): string {
		if (err instanceof ErrorCuentaRemota) return textoDiagnostico(err.diagnostico);
		return err instanceof Error ? err.message : porDefecto;
	}

	async function confirmarVinculacion(e: SubmitEvent) {
		e.preventDefault();
		errorVinculacion = undefined;
		sugerirCambiarCorreo = false;
		const claves = get(clavesDesbloqueadas);
		if (!claves) {
			errorVinculacion = $t.settingsSync.errorSinClaves;
			return;
		}
		vinculando = true;
		try {
			const url = serverUrl.replace(/\/+$/, '');
			if (modo === 'existente') {
				await vincularConCuentaExistente(url, email, claves);
			} else {
				await vincularComoBovedaNueva(url, email, displayName || email, claves);
			}
			vinculacion = obtenerVinculacion(email);
		} catch (err) {
			errorVinculacion = textoDeError(err, $t.settingsSync.errorGenerico);
			sugerirCambiarCorreo = err instanceof ErrorCuentaRemota && err.diagnostico.estado === 'no_autenticado';
		} finally {
			vinculando = false;
		}
	}

	// En sólo-memoria/sólo-nombres las contraseñas viven únicamente en el
	// servidor: desconectar dejaría sin poder verlas hasta volver a
	// conectarse, así que se pide una confirmación explícita.
	let confirmandoDesvinculo = $state(false);

	function alDesvincular() {
		if (persistencia !== 'full' && !confirmandoDesvinculo) {
			confirmandoDesvinculo = true;
			return;
		}
		confirmarDesvincular();
	}

	function confirmarDesvincular() {
		desvincular(email);
		vinculacion = null;
		confirmandoDesvinculo = false;
	}

	let sincronizando = $state(false);
	let ultimoResultado = $state<ResultadoSync | undefined>();
	let errorSync = $state<string | undefined>();

	async function alSincronizar() {
		errorSync = undefined;
		sincronizando = true;
		try {
			ultimoResultado = await sincronizarAhora();
		} catch (err) {
			errorSync = err instanceof Error ? err.message : $t.settingsSync.errorGenerico;
		} finally {
			sincronizando = false;
		}
	}

	// F-48 (spec/13 §8): los 3 modos sólo son elegibles con la bóveda
	// conectada — sin servidor no hay de dónde bajar un secreto bajo
	// demanda, así que "réplica completa" es la única opción real.
	const MODOS: { valor: ModoPersistencia; titulo: () => string; descripcion: () => string }[] = [
		{ valor: 'full', titulo: () => $t.settingsSync.modoFullTitulo, descripcion: () => $t.settingsSync.modoFullDescripcion },
		{ valor: 'memory', titulo: () => $t.settingsSync.modoMemoryTitulo, descripcion: () => $t.settingsSync.modoMemoryDescripcion },
		{ valor: 'names_only', titulo: () => $t.settingsSync.modoNamesOnlyTitulo, descripcion: () => $t.settingsSync.modoNamesOnlyDescripcion }
	];

	// Los modos sólo-memoria/sólo-nombres necesitan llegar al servidor para
	// ver una contraseña: en vez de un aviso fijo, se comprueba ahora si se
	// puede (y se vuelve a comprobar al cambiar la red y cada tanto).
	let estadoConexion = $state<EstadoConexion>('comprobando');
	$effect(() => {
		const servidor = vinculacion?.serverUrl;
		if (!servidor) return;
		let vigente = true;
		async function comprobar() {
			const alcanzable = await servidorAlcanzable(servidor as string);
			if (vigente) estadoConexion = alcanzable ? 'en_linea' : 'sin_conexion';
		}
		estadoConexion = 'comprobando';
		comprobar();
		const cada = setInterval(comprobar, 30_000);
		window.addEventListener('online', comprobar);
		window.addEventListener('offline', comprobar);
		return () => {
			vigente = false;
			clearInterval(cada);
			window.removeEventListener('online', comprobar);
			window.removeEventListener('offline', comprobar);
		};
	});

	function irAConectar() {
		document.getElementById('modo-conectado')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
	}

	let persistencia = $state<ModoPersistencia>('full');
	let cambiandoPersistencia = $state(false);
	let errorPersistencia = $state<string | undefined>();
	let avisoPersistencia = $state<string | undefined>();

	$effect(() => {
		obtenerPersistencia()
			.then((m) => (persistencia = m))
			.catch(() => {});
	});

	async function elegirPersistencia(modo: ModoPersistencia) {
		if (modo === persistencia || cambiandoPersistencia) return;
		if (modo !== 'full' && !vinculacion) return; // gating: sólo réplica completa sin servidor
		errorPersistencia = undefined;
		avisoPersistencia = undefined;
		cambiandoPersistencia = true;
		try {
			// Los modos que dependen del servidor (sólo-memoria/sólo-nombres)
			// se habilitan únicamente si la app puede validar que esta cuenta
			// existe y está habilitada allá — si no, el modo NO cambia y la
			// bóveda sigue local, en réplica completa.
			if (modo !== 'full' && vinculacion) {
				const claves = get(clavesDesbloqueadas);
				if (!claves) {
					errorPersistencia = $t.settingsSync.errorSinClaves;
					return;
				}
				const diagnostico = await diagnosticarCuentaRemota(vinculacion.serverUrl, email, claves);
				if (diagnostico.estado !== 'ok') {
					errorPersistencia = `${textoDiagnostico(diagnostico)} ${$t.settingsSync.persistenciaSigueLocal}`;
					sugerirCambiarCorreo = diagnostico.estado === 'no_autenticado';
					return;
				}
			}

			const anterior = persistencia;
			persistencia = await cambiarPersistencia(modo);

			// Volver a réplica completa: las contraseñas que se sincronizaron
			// sin su secreto no se rellenan solas con un cursor ya avanzado.
			if (modo === 'full' && anterior !== 'full' && vinculacion) {
				reiniciarCursor(email);
				avisoPersistencia = $t.settingsSync.persistenciaVolverAFullHint;
			}
		} catch (err) {
			errorPersistencia = textoDeError(err, $t.settingsSync.persistenciaErrorGenerico);
		} finally {
			cambiandoPersistencia = false;
		}
	}

	// Punto 7: diagnóstico del traspaso servidor <-> bóveda local, para el
	// modo activo. Sólo lee; el informe no lleva material secreto (ids y
	// banderas), así que se puede copiar y pegar.
	let verificando = $state(false);
	let informe = $state<InformeTraspaso | undefined>();
	let errorInforme = $state<string | undefined>();
	let informeCopiado = $state(false);

	const TITULO_MODO: Record<ModoPersistencia, () => string> = {
		full: () => $t.settingsSync.modoFullTitulo,
		memory: () => $t.settingsSync.modoMemoryTitulo,
		names_only: () => $t.settingsSync.modoNamesOnlyTitulo
	};

	async function alVerificar() {
		errorInforme = undefined;
		informeCopiado = false;
		verificando = true;
		try {
			informe = await verificarTraspaso();
		} catch (err) {
			informe = undefined;
			errorInforme = textoDeError(err, $t.settingsSync.errorGenerico);
		} finally {
			verificando = false;
		}
	}

	async function copiarInforme() {
		if (!informe) return;
		try {
			await navigator.clipboard.writeText(JSON.stringify(informe, null, 2));
			informeCopiado = true;
		} catch {
			informeCopiado = false;
		}
	}

	// Cuenta local: cambiar el correo (punto 6). Sólo con la bóveda
	// desconectada — ver `CambioEmailBloqueado`.
	let correoNuevo = $state('');
	let passphraseCorreo = $state('');
	let cambiandoCorreo = $state(false);
	let errorCorreo = $state<string | undefined>();
	let okCorreo = $state<string | undefined>();
	let avisoDesbloqueoRapido = $state(false);

	async function alCambiarCorreo(e: SubmitEvent) {
		e.preventDefault();
		errorCorreo = undefined;
		okCorreo = undefined;
		avisoDesbloqueoRapido = false;
		cambiandoCorreo = true;
		try {
			const resultado = await cambiarEmailLocal(correoNuevo, passphraseCorreo);
			okCorreo = $t.settingsSync.cuentaLocalOk.replace('{{email}}', resultado.email);
			avisoDesbloqueoRapido = resultado.desbloqueoRapidoDesactivado;
			correoNuevo = '';
			sugerirCambiarCorreo = false;
		} catch (err) {
			if (err instanceof CambioEmailBloqueado) {
				errorCorreo = $t.settingsSync.cuentaLocalBloqueada;
			} else if (err instanceof CambioEmailNoAplica) {
				errorCorreo = err.codigo === 'mismo_correo' ? $t.settingsSync.cuentaLocalMismoCorreo : $t.settingsSync.errorSinClaves;
			} else if (err instanceof ApiError) {
				errorCorreo = err.message;
			} else {
				// Lo único que falla sin ser un error del backend es abrir el blob
				// de la clave privada: contraseña incorrecta.
				errorCorreo = $t.settingsSync.cuentaLocalErrorPassphrase;
			}
		} finally {
			passphraseCorreo = '';
			cambiandoCorreo = false;
		}
	}
</script>

<svelte:head>
	<title>{$t.settingsSync.navTitulo} — Ellkan</title>
</svelte:head>

<div class="pila">
<div id="modo-conectado">
<Card>
	<h2>{$t.settingsSync.tituloModoConectado}</h2>
	<p class="hint">{$t.settingsSync.hintModoConectado}</p>

	{#if vinculacion}
		<p class="ok">{$t.settingsSync.conectadaA} <strong>{vinculacion.serverUrl}</strong></p>

		<div class="acciones">
			<Button variant="primary" onclick={alSincronizar} loading={sincronizando}>{$t.settingsSync.sincronizarAhora}</Button>
			<Button variant="danger" onclick={alDesvincular}>
				{confirmandoDesvinculo ? $t.settingsSync.desvincularDeTodosModos : $t.settingsSync.desvincular}
			</Button>
		</div>
		{#if confirmandoDesvinculo}
			<p class="error">{$t.settingsSync.desvincularAvisoModo}</p>
		{/if}

		{#if errorSync}<p class="error">{errorSync}</p>{/if}
		{#if ultimoResultado}
			<p class="ok">
				{$t.settingsSync.resultado
					.replace('{{recursos}}', String(ultimoResultado.recursosNuevosOActualizados))
					.replace('{{borrados}}', String(ultimoResultado.recursosBorrados))
					.replace('{{conflictos}}', String(ultimoResultado.recursosEnConflicto))
					.replace('{{carpetas}}', String(ultimoResultado.carpetasNuevas))
					.replace('{{tags}}', String(ultimoResultado.tagsNuevos))}
			</p>
			{#if ultimoResultado.recursosEnConflicto > 0}
				<p class="hint">{$t.settingsSync.hintConflictos}</p>
			{/if}
		{/if}

		{#if $estadoSync.ultimoError}
			<p class="error">{$t.settingsSync.ultimoPushFallo}: {$estadoSync.ultimoError}</p>
		{/if}
	{:else}
		<form onsubmit={confirmarVinculacion}>
			<TextField label={$t.settingsSync.servidorUrl} bind:value={serverUrl} placeholder="https://ellkan.miempresa.com" required />

			<label class="modo">
				<input type="radio" bind:group={modo} value="existente" />
				{$t.settingsSync.modoYaTengoCuenta}
			</label>
			<label class="modo">
				<input type="radio" bind:group={modo} value="nueva" />
				{$t.settingsSync.modoBovedaNueva}
			</label>

			{#if modo === 'nueva'}
				<TextField label={$t.settingsSync.nombreParaElServidor} bind:value={displayName} placeholder={email} />
			{/if}

			{#if errorVinculacion}<p class="error">{errorVinculacion}</p>{/if}
			{#if sugerirCambiarCorreo}<p class="hint">{$t.settingsSync.hintCambiarCorreo}</p>{/if}
			<Button type="submit" variant="primary" loading={vinculando}>{$t.settingsSync.vincular}</Button>
		</form>
	{/if}
</Card>
</div>

<Card>
	<h2>{$t.settingsSync.persistenciaTitulo}</h2>
	<p class="hint">{$t.settingsSync.persistenciaHint}</p>
	{#if !vinculacion}
		<p class="hint">{$t.settingsSync.persistenciaSoloLocalHint}</p>
		<div class="acciones">
			<Button onclick={irAConectar}>{$t.settingsSync.irAConectar}</Button>
		</div>
	{/if}

	<div class="cajones">
		{#each MODOS as m (m.valor)}
			{@const deshabilitado = m.valor !== 'full' && !vinculacion}
			<button
				type="button"
				class="cajon"
				class:activo={persistencia === m.valor}
				disabled={deshabilitado || cambiandoPersistencia}
				onclick={() => elegirPersistencia(m.valor)}
			>
				<span class="cajonTitulo">{m.titulo()}</span>
				<span class="cajonDescripcion">{m.descripcion()}</span>
				{#if m.valor !== 'full'}
					{#if !vinculacion}
						<span class="cajonDescripcion">{$t.settingsSync.persistenciaRequiereServidor}</span>
					{:else if estadoConexion === 'en_linea'}
						<span class="cajonOk">{$t.settingsSync.conexionOk}</span>
					{:else if estadoConexion === 'sin_conexion'}
						<span class="cajonAviso">{$t.settingsSync.conexionCaida}</span>
					{:else}
						<span class="cajonDescripcion">{$t.settingsSync.conexionComprobando}</span>
					{/if}
				{/if}
			</button>
		{/each}
	</div>

	{#if cambiandoPersistencia}<p class="hint">{$t.settingsSync.persistenciaValidando}</p>{/if}
	{#if errorPersistencia}<p class="error">{errorPersistencia}</p>{/if}
	{#if sugerirCambiarCorreo && errorPersistencia}<p class="hint">{$t.settingsSync.hintCambiarCorreo}</p>{/if}
	{#if avisoPersistencia}<p class="ok">{avisoPersistencia}</p>{/if}
</Card>

<Card>
	<h2>{$t.settingsSync.cuentaLocalTitulo}</h2>
	<p class="hint">{$t.settingsSync.cuentaLocalHint}</p>
	<p class="ok">{$t.settingsSync.cuentaLocalCorreoActual}: <strong>{email}</strong></p>

	{#if vinculacion}
		<p class="hint">{$t.settingsSync.cuentaLocalBloqueada}</p>
	{:else}
		<form onsubmit={alCambiarCorreo}>
			<TextField label={$t.settingsSync.cuentaLocalNuevoCorreo} type="email" bind:value={correoNuevo} autocomplete="email" required />
			<TextField label={$t.settingsSync.cuentaLocalPassphrase} type="password" bind:value={passphraseCorreo} autocomplete="current-password" required />
			{#if errorCorreo}<p class="error">{errorCorreo}</p>{/if}
			<Button type="submit" variant="primary" loading={cambiandoCorreo}>{$t.settingsSync.cuentaLocalCambiar}</Button>
		</form>
	{/if}

	{#if okCorreo}<p class="ok">{okCorreo}</p>{/if}
	{#if avisoDesbloqueoRapido}<p class="hint">{$t.settingsSync.cuentaLocalDesbloqueoRapido}</p>{/if}
</Card>

{#if vinculacion}
	<Card>
		<h2>{$t.settingsSync.traspasoTitulo}</h2>
		<p class="hint">{$t.settingsSync.traspasoHint}</p>

		<div class="acciones">
			<Button variant="primary" onclick={alVerificar} loading={verificando}>{$t.settingsSync.traspasoVerificar}</Button>
			{#if informe}
				<Button onclick={copiarInforme}>{informeCopiado ? $t.settingsSync.traspasoCopiado : $t.settingsSync.traspasoCopiar}</Button>
			{/if}
		</div>

		{#if errorInforme}<p class="error">{errorInforme}</p>{/if}

		{#if informe}
			<p class={informe.sano ? 'ok' : 'error'}>
				{informe.sano ? $t.settingsSync.traspasoSano : $t.settingsSync.traspasoConErrores}
			</p>
			<p class="hint">
				{$t.settingsSync.traspasoResumen
					.replace('{{modo}}', TITULO_MODO[informe.modo]())
					.replace('{{remotos}}', String(informe.totalRemotos))
					.replace('{{locales}}', String(informe.totalLocales))
					.replace('{{ok}}', String(informe.sinHallazgos))
					.replace('{{errores}}', String(informe.errores))
					.replace('{{avisos}}', String(informe.avisos))
					.replace('{{infos}}', String(informe.infos))}
			</p>
			{#if informe.hallazgos.length > 0}
				<ul class="hallazgos">
					{#each informe.hallazgos as h (h.tipo + h.id)}
						<li class:hallazgoError={h.severidad === 'error'} class:hallazgoAviso={h.severidad === 'aviso'}>
							<code>{h.id.slice(0, 8)}</code> — {h.detalle}
						</li>
					{/each}
				</ul>
			{/if}
		{/if}
	</Card>
{/if}
</div>


<style>
	.pila {
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
	}
	.hint {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-4) 0;
	}
	.ok {
		color: var(--success);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-2) 0;
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
		margin: var(--space-2) 0;
	}
	.acciones {
		display: flex;
		gap: var(--space-2);
		margin-bottom: var(--space-2);
	}
	.modo {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-sm);
		color: var(--text-primary);
		margin: var(--space-2) 0;
	}
	form {
		display: flex;
		flex-direction: column;
	}
	.cajones {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.cajon {
		display: flex;
		flex-direction: column;
		align-items: flex-start;
		gap: var(--space-1);
		text-align: left;
		width: 100%;
		padding: var(--space-3);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-md);
		background: var(--bg-raised);
		cursor: pointer;
	}
	.cajon:disabled {
		cursor: not-allowed;
		opacity: 0.5;
	}
	.cajon.activo {
		border-color: var(--accent-primary);
	}
	.cajonTitulo {
		font-weight: 600;
		color: var(--text-primary);
	}
	.cajonDescripcion {
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.cajonAviso {
		font-size: var(--text-sm);
		color: var(--warning);
	}
	.cajonOk {
		font-size: var(--text-sm);
		color: var(--success);
	}
	.hallazgos {
		margin: var(--space-2) 0 0 0;
		padding-left: var(--space-4);
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.hallazgos li {
		margin: var(--space-1) 0;
	}
	.hallazgos li.hallazgoError {
		color: var(--danger);
	}
	.hallazgos li.hallazgoAviso {
		color: var(--warning);
	}
</style>
