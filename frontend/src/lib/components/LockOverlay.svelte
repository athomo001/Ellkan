<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-39: overlay de auto-bloqueo — cubre el contenido sin desmontarlo y
	// sin tocar la sesión HTTP (`sesion` store nunca se limpia acá, sólo
	// `clavesDesbloqueadas` ya se limpió antes de mostrar esto). Reanuda con
	// passphrase o con el código local de F-38 si está activo en este
	// dispositivo.
	import { get } from 'svelte/store';
	import TextField from './TextField.svelte';
	import Button from './Button.svelte';
	import { desbloquearConPassphrase } from '$lib/crypto/identity';
	import { desbloquear as desbloquearLocal, estaActivo } from '$lib/crypto/totp-local';
	import { clavesDesbloqueadas } from '$lib/state/session';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let { email, onDesbloqueado }: { email: string; onDesbloqueado: () => void } = $props();

	let conCodigoLocal = $state(false);
	let passphrase = $state('');
	let codigo = $state('');
	let cargando = $state(false);
	let error = $state<string | undefined>();

	const codigoLocalDisponible = $derived(email ? estaActivo(email) : false);

	async function conPassphrase(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;
		cargando = true;
		try {
			clavesDesbloqueadas.set(await desbloquearConPassphrase(email, passphrase));
			passphrase = '';
			onDesbloqueado();
		} catch {
			error = get(t).lockOverlay.errorPassphrase;
		} finally {
			cargando = false;
		}
	}

	async function conCodigo(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;
		cargando = true;
		try {
			const passphraseRecuperada = await desbloquearLocal(email, codigo);
			clavesDesbloqueadas.set(await desbloquearConPassphrase(email, passphraseRecuperada));
			codigo = '';
			onDesbloqueado();
		} catch (err) {
			error = err instanceof ApiError || err instanceof Error ? err.message : get(t).lockOverlay.errorCodigo;
		} finally {
			cargando = false;
		}
	}
</script>

<div class="overlay" role="alertdialog" aria-modal="true" aria-label={$t.lockOverlay.titulo}>
	<div class="panel">
		<h2>{$t.lockOverlay.titulo}</h2>
		<p class="hint">{email} {$t.lockOverlay.hint}</p>

		{#if conCodigoLocal}
			<form onsubmit={conCodigo}>
				<TextField label={$t.lockOverlay.codigoLocal} bind:value={codigo} autocomplete="one-time-code" required />
				{#if error}<p class="error">{error}</p>{/if}
				<Button type="submit" variant="primary" loading={cargando}>{$t.lockOverlay.desbloquear}</Button>
			</form>
			<p class="hint">
				<button type="button" class="link" onclick={() => (conCodigoLocal = false)}
					>{$t.lockOverlay.usarPassphrase}</button
				>
			</p>
		{:else}
			<form onsubmit={conPassphrase}>
				<TextField
					label={$t.lockOverlay.passphrase}
					type="password"
					bind:value={passphrase}
					autocomplete="current-password"
					required
				/>
				{#if error}<p class="error">{error}</p>{/if}
				<Button type="submit" variant="primary" loading={cargando}>{$t.lockOverlay.desbloquear}</Button>
			</form>
			{#if codigoLocalDisponible}
				<p class="hint">
					<button type="button" class="link" onclick={() => (conCodigoLocal = true)}
						>{$t.lockOverlay.usarCodigoLocal}</button
					>
				</p>
			{/if}
		{/if}
	</div>
</div>

<style>
	.overlay {
		position: fixed;
		inset: 0;
		z-index: 100;
		display: flex;
		align-items: center;
		justify-content: center;
		background: color-mix(in srgb, var(--bg-base) 92%, transparent);
		backdrop-filter: blur(4px);
	}
	.panel {
		width: 100%;
		max-width: 22rem;
		background: var(--bg-raised);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-md);
		padding: var(--space-6);
	}
	h2 {
		margin: 0 0 var(--space-2) 0;
		font-size: var(--text-lg);
		color: var(--text-primary);
	}
	form {
		display: flex;
		flex-direction: column;
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
	.link {
		background: none;
		border: none;
		padding: 0;
		font: inherit;
		color: var(--accent-primary);
		cursor: pointer;
	}
</style>
