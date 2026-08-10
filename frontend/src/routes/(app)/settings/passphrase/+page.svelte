<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-01: "Frase de contraseña" — sección de "Mi cuenta", la más sensible
	// de las 7. Cambiar la passphrase rota `security_stamp` server-side e
	// invalida toda sesión activa, incluida ésta — se trata como éxito, no
	// como error, y se redirige a login.
	import { get } from 'svelte/store';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import { cambiarPassphrase, cerrarSesion } from '$lib/crypto/identity';
	import { evaluarFortaleza } from '$lib/crypto/passwordStrength';
	import { sesion } from '$lib/state/session';
	import { goto } from '$app/navigation';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	const email = $derived($sesion.email ?? '');

	let passphraseActual = $state('');
	let passphraseNueva = $state('');
	let passphraseConfirmacion = $state('');
	let cambiando = $state(false);
	let error = $state<string | undefined>();
	let listo = $state(false);
	const fortaleza = $derived(evaluarFortaleza(passphraseNueva));
	const labelFortaleza = $derived(
		[
			get(t).fortalezaPassword.muyDebil,
			get(t).fortalezaPassword.debil,
			get(t).fortalezaPassword.aceptable,
			get(t).fortalezaPassword.fuerte,
			get(t).fortalezaPassword.muyFuerte
		][fortaleza.score]
	);

	async function enviar(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;
		if (passphraseNueva !== passphraseConfirmacion) {
			error = get(t).settingsProfile.passphraseErrorNoCoinciden;
			return;
		}
		if (fortaleza.score < 3) {
			error = get(t).settingsProfile.passphraseErrorDebil;
			return;
		}
		cambiando = true;
		try {
			await cambiarPassphrase(email, passphraseActual, passphraseNueva);
			listo = true;
			setTimeout(async () => {
				await cerrarSesion().catch(() => {});
				goto('/login');
			}, 1500);
		} catch (err) {
			error =
				err instanceof ApiError || err instanceof Error
					? get(t).settingsProfile.passphraseErrorActual
					: get(t).settingsProfile.passphraseErrorGenerico;
		} finally {
			cambiando = false;
		}
	}
</script>

<svelte:head>
	<title>{$t.settingsProfile.passphraseTitulo} — Ellkan</title>
</svelte:head>

<h1>{$t.settingsProfile.passphraseTitulo}</h1>
<Card>
	<p class="hint">{$t.settingsProfile.passphraseHint}</p>
	{#if listo}
		<p class="ok">{$t.settingsProfile.passphraseListo}</p>
	{:else}
		<form onsubmit={enviar}>
			<TextField
				label={$t.settingsProfile.passphraseActual}
				type="password"
				bind:value={passphraseActual}
				autocomplete="current-password"
				required
			/>
			<TextField
				label={$t.settingsProfile.passphraseNueva}
				type="password"
				bind:value={passphraseNueva}
				autocomplete="new-password"
				required
			/>
			{#if passphraseNueva}
				<p class="fortaleza fortaleza-{fortaleza.score}">{labelFortaleza}</p>
			{/if}
			<TextField
				label={$t.settingsProfile.passphraseConfirmar}
				type="password"
				bind:value={passphraseConfirmacion}
				autocomplete="new-password"
				required
			/>
			{#if error}<p class="error">{error}</p>{/if}
			<Button type="submit" variant="primary" loading={cambiando}>{$t.settingsProfile.passphraseCambiar}</Button>
		</form>
	{/if}
</Card>

<style>
	h1 {
		margin: 0 0 var(--space-6) 0;
		font-size: var(--text-2xl);
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
	form {
		display: flex;
		flex-direction: column;
		max-width: 24rem;
	}
	.fortaleza {
		margin: calc(-1 * var(--space-2)) 0 var(--space-4) 0;
		font-size: var(--text-xs);
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
</style>
