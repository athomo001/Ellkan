<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-01: genera el keypair y sella la clave privada client-side antes de
	// que nada viaje al servidor — el servidor sólo recibe claves públicas
	// y un blob ya cifrado (identity.ts::registrar).
	import { goto } from '$app/navigation';
	import { get } from 'svelte/store';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import Card from '$lib/components/Card.svelte';
	import { registrar } from '$lib/crypto/identity';
	import { evaluarFortaleza } from '$lib/crypto/passwordStrength';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let email = $state('');
	let displayName = $state('');
	let passphrase = $state('');
	let passphraseConfirmar = $state('');
	let cargando = $state(false);
	let error = $state<string | undefined>();

	// F-01: sin medidor client-side hasta ahora — F-27 lo exige para la
	// contraseña de un export KDBX "vía el mismo medidor que la passphrase
	// de cuenta", así que se agrega acá primero (única fuente) y F-27 lo
	// reusa (`settings/export-import`). No bloquea el submit — el backend
	// sigue siendo quien aplica `min_passphrase_entropy_bits` (F-24).
	const fortaleza = $derived(evaluarFortaleza(passphrase));
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

		if (passphrase !== passphraseConfirmar) {
			error = get(t).registro.errorNoCoinciden;
			return;
		}

		cargando = true;
		try {
			await registrar(email, displayName, passphrase);
			goto('/login');
		} catch (err) {
			error = err instanceof ApiError ? err.message : get(t).registro.errorGenerico;
		} finally {
			cargando = false;
		}
	}
</script>

<svelte:head>
	<title>{$t.registro.titulo}</title>
</svelte:head>

<Card>
	<h1>{$t.registro.crearCuenta}</h1>
	<p class="subtitulo">{$t.registro.subtitulo}</p>
	<form onsubmit={enviar}>
		<TextField label={$t.registro.nombre} bind:value={displayName} autocomplete="name" required />
		<TextField label={$t.registro.email} type="email" bind:value={email} autocomplete="email" required />
		<TextField
			label={$t.registro.passphrase}
			type="password"
			bind:value={passphrase}
			autocomplete="new-password"
			hint={$t.registro.passphraseHint}
			required
		/>
		{#if passphrase}
			<p class="fortaleza fortaleza-{fortaleza.score}">{labelFortaleza}</p>
		{/if}
		<TextField
			label={$t.registro.confirmarPassphrase}
			type="password"
			bind:value={passphraseConfirmar}
			autocomplete="new-password"
			required
		/>
		{#if error}<p class="error">{error}</p>{/if}
		<Button type="submit" variant="primary" loading={cargando}>{$t.registro.crearCuenta}</Button>
	</form>
	<p class="hint">{$t.registro.yaTenesCuenta} <a href="/login">{$t.registro.iniciaSesion}</a></p>
</Card>

<style>
	h1 {
		margin: 0;
		font-size: var(--text-2xl);
		color: var(--text-primary);
	}
	.subtitulo {
		margin: var(--space-2) 0 var(--space-6) 0;
		color: var(--text-secondary);
		font-size: var(--text-sm);
	}
	form {
		display: flex;
		flex-direction: column;
	}
	.hint {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin-top: var(--space-4);
		text-align: center;
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-4) 0;
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
	a {
		color: var(--accent-primary);
	}
</style>
