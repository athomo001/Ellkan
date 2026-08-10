<!-- Autor: Athan Espinoza -->
<script lang="ts">
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import { selfRegistrationPolicyApi, smtpConfigApi } from '$lib/api/admin';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let cargando = $state(true);
	let guardando = $state(false);
	let error = $state<string | undefined>();
	let guardado = $state(false);
	let smtpConfigurado = $state(true);

	let enabled = $state(true);
	let allowedDomains = $state('');

	onMount(async () => {
		try {
			const [p, smtp] = await Promise.all([selfRegistrationPolicyApi.obtener(), smtpConfigApi.obtener()]);
			enabled = p.enabled;
			allowedDomains = p.allowed_domains.join('\n');
			smtpConfigurado = smtp.configurado;
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
			await selfRegistrationPolicyApi.actualizar({
				enabled,
				allowed_domains: allowedDomains
					.split('\n')
					.map((s) => s.trim())
					.filter(Boolean)
			});
			guardado = true;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			guardando = false;
		}
	}
</script>

<h1>{$t.admin.politicaSelfRegistration.titulo}</h1>
<Card>
	{#if cargando}
		<p>{$t.admin.comun.cargando}</p>
	{:else}
		{#if !smtpConfigurado}
			<p class="aviso">{$t.admin.politicaSelfRegistration.avisoSmtp}</p>
		{/if}
		<form onsubmit={guardar}>
			<label class="check"><input type="checkbox" bind:checked={enabled} /> {$t.admin.politicaSelfRegistration.habilitado}</label>
			<div class="field">
				<label for="dominios">{$t.admin.politicaSelfRegistration.dominiosPermitidos}</label>
				<textarea id="dominios" bind:value={allowedDomains} rows="4" placeholder="ejemplo.com"></textarea>
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
	label {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		font-weight: 500;
	}
	.check {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		margin-bottom: var(--space-4);
	}
	input,
	textarea {
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
		color: var(--text-primary);
		font-family: inherit;
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
	}
	.ok {
		color: var(--success);
		font-size: var(--text-sm);
	}
	.aviso {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-3);
		margin: 0 0 var(--space-4) 0;
	}
</style>
