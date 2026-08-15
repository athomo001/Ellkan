<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-27: política de export/import — mismo skeleton que
	// `policies/password/+page.svelte`. `export_enabled` es el interruptor
	// maestro (con excepción admin/owner sólo sobre este campo, nunca sobre
	// `allowed_formats`/`import_enabled` — la excepción la aplica el
	// servidor en `POST /export-events`, acá sólo se edita la política).
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import { adminExportPolicyApi, type ExportPolicy } from '$lib/api/exportPolicy';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let cargando = $state(true);
	let guardando = $state(false);
	let error = $state<string | undefined>();
	let guardado = $state(false);

	let exportEnabled = $state(true);
	let importEnabled = $state(true);
	let kdbx = $state(true);
	let csv = $state(false);
	let cxf = $state(false);

	onMount(async () => {
		try {
			const p = await adminExportPolicyApi.obtener();
			exportEnabled = p.export_enabled;
			importEnabled = p.import_enabled;
			kdbx = p.allowed_formats.includes('kdbx');
			csv = p.allowed_formats.includes('csv');
			cxf = p.allowed_formats.includes('cxf');
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			cargando = false;
		}
	});

	async function guardar(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;
		guardado = false;
		guardando = true;
		try {
			const allowed_formats: string[] = [];
			if (kdbx) allowed_formats.push('kdbx');
			if (csv) allowed_formats.push('csv');
			if (cxf) allowed_formats.push('cxf');
			const p: ExportPolicy = { export_enabled: exportEnabled, import_enabled: importEnabled, allowed_formats };
			await adminExportPolicyApi.actualizar(p);
			guardado = true;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			guardando = false;
		}
	}
</script>

<h1>{$t.admin.politicaExport.titulo}</h1>
<Card>
	{#if cargando}
		<p>{$t.admin.comun.cargando}</p>
	{:else}
		<form onsubmit={guardar}>
			<label class="check">
				<input type="checkbox" bind:checked={exportEnabled} />
				{$t.admin.politicaExport.exportEnabled}
			</label>
			<p class="hint">{$t.admin.politicaExport.exportEnabledHint}</p>

			<label class="check">
				<input type="checkbox" bind:checked={importEnabled} />
				{$t.admin.politicaExport.importEnabled}
			</label>

			<div class="field">
				<span class="label">{$t.admin.politicaExport.formatosPermitidos}</span>
				<label class="check"><input type="checkbox" bind:checked={kdbx} /> {$t.admin.politicaExport.formatoKdbx}</label>
				<label class="check"><input type="checkbox" bind:checked={csv} /> {$t.admin.politicaExport.formatoCsv}</label>
				<label class="check"><input type="checkbox" bind:checked={cxf} /> {$t.admin.politicaExport.formatoCxf}</label>
			</div>

			{#if error}<p class="error">{error}</p>{/if}
			{#if guardado}<p class="ok">{$t.admin.comun.guardado}</p>{/if}
			<Button type="submit" variant="primary" loading={guardando}>{$t.admin.comun.guardar}</Button>
		</form>
	{/if}
</Card>

<style>
	h1 {
		margin: 0 0 var(--space-6) 0;
		font-size: var(--text-2xl);
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
	.label {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		font-weight: 500;
	}
	.check {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-sm);
		color: var(--text-primary);
		margin-bottom: var(--space-2);
	}
	.hint {
		color: var(--text-muted);
		font-size: var(--text-xs);
		margin: 0 0 var(--space-4) 0;
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
