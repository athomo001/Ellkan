<!-- Autor: Athan Espinoza -->
<script lang="ts">
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import { passwordPolicyApi, type PasswordPolicy } from '$lib/api/admin';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let cargando = $state(true);
	let guardando = $state(false);
	let error = $state<string | undefined>();
	let guardado = $state(false);
	let cargas: PasswordPolicy | undefined;

	let minLength = $state('12');
	let minEntropy = $state('60');
	let rotationDays = $state('');
	let generatorLength = $state('20');
	let clipboardCeiling = $state('');
	let autoLockCeiling = $state('');

	onMount(async () => {
		try {
			const p = await passwordPolicyApi.obtener();
			cargas = p;
			minLength = String(p.min_passphrase_length);
			minEntropy = String(p.min_passphrase_entropy_bits);
			rotationDays = p.passphrase_rotation_days === null ? '' : String(p.passphrase_rotation_days);
			generatorLength = String(p.generator_default_length);
			clipboardCeiling = p.max_clipboard_clear_minutes === null ? '' : String(p.max_clipboard_clear_minutes);
			autoLockCeiling = p.max_auto_lock_minutes === null ? '' : String(p.max_auto_lock_minutes);
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
			await passwordPolicyApi.actualizar({
				min_passphrase_length: Number(minLength),
				min_passphrase_entropy_bits: Number(minEntropy),
				passphrase_rotation_days: rotationDays === '' ? null : Number(rotationDays),
				generator_default_length: Number(generatorLength),
				generator_charset_rules: cargas?.generator_charset_rules ?? {},
				max_clipboard_clear_minutes: clipboardCeiling === '' ? null : Number(clipboardCeiling),
				max_auto_lock_minutes: autoLockCeiling === '' ? null : Number(autoLockCeiling)
			});
			guardado = true;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			guardando = false;
		}
	}
</script>

<h1>{$t.admin.politicaPassword.titulo}</h1>
<Card>
	{#if cargando}
		<p>{$t.admin.comun.cargando}</p>
	{:else}
		<form onsubmit={guardar}>
			<div class="field">
				<label for="minlen">{$t.admin.politicaPassword.minLongitud}</label>
				<input id="minlen" type="number" min="12" bind:value={minLength} />
			</div>
			<div class="field">
				<label for="minent">{$t.admin.politicaPassword.minEntropia}</label>
				<input id="minent" type="number" min="0" bind:value={minEntropy} />
			</div>
			<div class="field">
				<label for="rot">{$t.admin.politicaPassword.rotacionDias}</label>
				<input id="rot" type="number" min="1" bind:value={rotationDays} />
			</div>
			<div class="field">
				<label for="genlen">{$t.admin.politicaPassword.generadorLongitud}</label>
				<input id="genlen" type="number" min="1" bind:value={generatorLength} />
			</div>
			<div class="field">
				<label for="clipceil">{$t.admin.politicaPassword.techoPortapapeles}</label>
				<input id="clipceil" type="number" min="0" bind:value={clipboardCeiling} />
			</div>
			<div class="field">
				<label for="lockceil">{$t.admin.politicaPassword.techoAutoBloqueo}</label>
				<input id="lockceil" type="number" min="1" bind:value={autoLockCeiling} />
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
	input {
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
		color: var(--text-primary);
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
