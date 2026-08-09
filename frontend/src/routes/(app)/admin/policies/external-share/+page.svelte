<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-26: política de External Secure Share — mismo skeleton que
	// `policies/export/+page.svelte`.
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import { adminExternalSharePolicyApi, type ExternalSharePolicy } from '$lib/api/externalShares';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let cargando = $state(true);
	let guardando = $state(false);
	let error = $state<string | undefined>();
	let guardado = $state(false);

	let enabled = $state(true);
	let maxExpirationHours = $state('168');
	let requirePassword = $state(false);

	onMount(async () => {
		try {
			const p = await adminExternalSharePolicyApi.obtener();
			enabled = p.enabled;
			maxExpirationHours = String(p.max_expiration_hours);
			requirePassword = p.require_password;
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
			const p: ExternalSharePolicy = {
				enabled,
				max_expiration_hours: Number(maxExpirationHours),
				require_password: requirePassword
			};
			await adminExternalSharePolicyApi.actualizar(p);
			guardado = true;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			guardando = false;
		}
	}
</script>

<h1>{$t.admin.politicaExternalShare.titulo}</h1>
<Card>
	{#if cargando}
		<p>{$t.admin.comun.cargando}</p>
	{:else}
		<form onsubmit={guardar}>
			<label class="check">
				<input type="checkbox" bind:checked={enabled} />
				{$t.admin.politicaExternalShare.enabled}
			</label>

			<TextField
				label={$t.admin.politicaExternalShare.maxExpirationHours}
				type="number"
				bind:value={maxExpirationHours}
				required
			/>

			<label class="check">
				<input type="checkbox" bind:checked={requirePassword} />
				{$t.admin.politicaExternalShare.requirePassword}
			</label>

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
	.check {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-sm);
		color: var(--text-primary);
		margin-bottom: var(--space-4);
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
