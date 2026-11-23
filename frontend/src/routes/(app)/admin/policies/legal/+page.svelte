<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// Pendiente #57: links a la política de privacidad y a los términos de la
	// instancia. El registro y el login los muestran. Vacío = sin link.
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import { legalLinksApi } from '$lib/api/admin';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let cargando = $state(true);
	let guardando = $state(false);
	let error = $state<string | undefined>();
	let guardado = $state(false);

	let privacidad = $state('');
	let terminos = $state('');

	onMount(async () => {
		try {
			const l = await legalLinksApi.obtener();
			privacidad = l.privacy_url ?? '';
			terminos = l.terms_url ?? '';
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
			const l = await legalLinksApi.actualizar({ privacy_url: privacidad, terms_url: terminos });
			privacidad = l.privacy_url ?? '';
			terminos = l.terms_url ?? '';
			guardado = true;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			guardando = false;
		}
	}
</script>

<h1>{$t.admin.politicaLegal.titulo}</h1>
<Card>
	{#if cargando}
		<p>{$t.admin.comun.cargando}</p>
	{:else}
		<p class="hint">{$t.admin.politicaLegal.hint}</p>
		<form onsubmit={guardar}>
			<div class="field">
				<label for="privacidad">{$t.admin.politicaLegal.privacidad}</label>
				<input id="privacidad" type="url" placeholder="https://" bind:value={privacidad} />
			</div>
			<div class="field">
				<label for="terminos">{$t.admin.politicaLegal.terminos}</label>
				<input id="terminos" type="url" placeholder="https://" bind:value={terminos} />
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
		max-width: 32rem;
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		margin-bottom: var(--space-4);
	}
	label {
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	input {
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
		color: var(--text-primary);
	}
	.hint {
		color: var(--text-secondary);
		font-size: var(--text-sm);
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
