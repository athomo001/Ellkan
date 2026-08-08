<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-27: export/import personal de recursos (KDBX/CSV/CXF), 100%
	// client-side, gobernado por `export_policy`. El cliente oculta la
	// opción si la política la desactiva y el usuario no es admin/owner,
	// pero el servidor sigue siendo la fuente de verdad (`POST
	// /export-events`, ver `$lib/crypto/exportImport.ts`) — un intento
	// forzado igual falla explícito del lado servidor.
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
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
	import { sesion, clavesDesbloqueadas } from '$lib/state/session';
	import { desbloquearConPassphrase } from '$lib/crypto/identity';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let cargandoPolitica = $state(true);
	let politica = $state<ExportPolicy | undefined>();
	let excepcionAdmin = $state(false);

	// Passkey sin PRF puede dejar `clavesDesbloqueadas` vacío (mismo patrón que `vault/+page.svelte`).
	let passphraseDesbloqueo = $state('');
	let desbloqueando = $state(false);
	let errorDesbloqueo = $state<string | undefined>();

	async function desbloquear(e: SubmitEvent) {
		e.preventDefault();
		errorDesbloqueo = undefined;
		desbloqueando = true;
		try {
			clavesDesbloqueadas.set(await desbloquearConPassphrase($sesion.email ?? '', passphraseDesbloqueo));
			passphraseDesbloqueo = '';
		} catch {
			errorDesbloqueo = $t.lockOverlay.errorPassphrase;
		} finally {
			desbloqueando = false;
		}
	}

	onMount(async () => {
		try {
			politica = await exportPolicyApi.obtener();
		} catch {
			/* si esto falla, el resto de la pantalla queda oculta — no hay política que gatee nada */
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
	});

	const puedeExportar = $derived(!!politica && (politica.export_enabled || excepcionAdmin));
	const puedeImportar = $derived(!!politica && politica.import_enabled);
	const formatosDisponibles = $derived((politica?.allowed_formats ?? []) as FormatoExport[]);

	// --- export ---
	let formatoExport = $state<FormatoExport>('kdbx');
	let passwordExport = $state('');
	let exportando = $state(false);
	let errorExport = $state<string | undefined>();
	let okExport = $state<number | undefined>();

	const fortalezaExport = $derived(evaluarFortaleza(passwordExport));
	const labelFortaleza = $derived(
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
			const { filas } = await construirFilasExport($clavesDesbloqueadas);
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

	// --- import ---
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
		} catch (err) {
			errorImport = err instanceof ApiError ? err.message : err instanceof Error ? err.message : $t.exportImport.errorImportar;
		} finally {
			importando = false;
		}
	}
</script>

<svelte:head>
	<title>{$t.exportImport.titulo} — Ellkan</title>
</svelte:head>

<h1>{$t.exportImport.titulo}</h1>

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
{:else if cargandoPolitica}
	<Card><p>{$t.exportImport.cargandoPolitica}</p></Card>
{:else if !puedeExportar && !puedeImportar}
	<Card><p class="hint">{$t.exportImport.sinFormatosHabilitados}</p></Card>
{:else}
	{#if politica && !politica.export_enabled && excepcionAdmin}
		<p class="hint aviso">{$t.exportImport.viaExcepcionAdmin}</p>
	{/if}

	{#if puedeExportar}
		<Card>
			<h2>{$t.exportImport.exportarTitulo}</h2>
			<p class="hint">{$t.exportImport.exportarHint}</p>
			<form onsubmit={hacerExport}>
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
						<p class="fortaleza fortaleza-{fortalezaExport.score}">{labelFortaleza}</p>
					{/if}
				{/if}
				{#if errorExport}<p class="error">{errorExport}</p>{/if}
				{#if okExport !== undefined}<p class="ok">{$t.exportImport.exportadoOk(okExport)}</p>{/if}
				<Button type="submit" variant="primary" loading={exportando}>{$t.exportImport.exportar}</Button>
			</form>
		</Card>
	{/if}

	{#if puedeImportar}
		<Card>
			<h2>{$t.exportImport.importarTitulo}</h2>
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
		</Card>
	{/if}
{/if}

<style>
	h1 {
		margin: 0 0 var(--space-6) 0;
		font-size: var(--text-2xl);
		color: var(--text-primary);
	}
	h2 {
		margin: 0 0 var(--space-2) 0;
		font-size: var(--text-lg);
		color: var(--text-primary);
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
	select,
	input[type='file'] {
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
		color: var(--text-primary);
	}
	.hint {
		color: var(--text-muted);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-4) 0;
	}
	.aviso {
		color: var(--text-secondary);
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
	}
	.ok {
		color: var(--success);
		font-size: var(--text-sm);
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
		color: var(--text-secondary);
	}
	.fortaleza-3,
	.fortaleza-4 {
		color: var(--success);
	}
</style>
