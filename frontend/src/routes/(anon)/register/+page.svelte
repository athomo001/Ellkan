<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-01: genera el keypair y sella la clave privada client-side antes de
	// que nada viaje al servidor — el servidor sólo recibe claves públicas
	// y un blob ya cifrado (identity.ts::registrar).
	import { goto } from '$app/navigation';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import Card from '$lib/components/Card.svelte';
	import { registrar } from '$lib/crypto/identity';
	import { ApiError } from '$lib/api/client';

	let email = $state('');
	let displayName = $state('');
	let passphrase = $state('');
	let passphraseConfirmar = $state('');
	let cargando = $state(false);
	let error = $state<string | undefined>();

	async function enviar(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;

		if (passphrase !== passphraseConfirmar) {
			error = 'Las passphrases no coinciden.';
			return;
		}

		cargando = true;
		try {
			await registrar(email, displayName, passphrase);
			goto('/login');
		} catch (err) {
			error = err instanceof ApiError ? err.message : 'No se pudo completar el registro.';
		} finally {
			cargando = false;
		}
	}
</script>

<svelte:head>
	<title>Crear cuenta — Ellkan</title>
</svelte:head>

<Card>
	<h1>Ellkan</h1>
	<form onsubmit={enviar}>
		<TextField label="Nombre" bind:value={displayName} autocomplete="name" required />
		<TextField label="Email" type="email" bind:value={email} autocomplete="email" required />
		<TextField
			label="Passphrase"
			type="password"
			bind:value={passphrase}
			autocomplete="new-password"
			hint="Se valida client-side, nunca viaja en claro al servidor."
			required
		/>
		<TextField
			label="Confirmar passphrase"
			type="password"
			bind:value={passphraseConfirmar}
			autocomplete="new-password"
			required
		/>
		{#if error}<p class="error">{error}</p>{/if}
		<Button type="submit" variant="primary" loading={cargando}>Crear cuenta</Button>
	</form>
	<p class="hint">¿Ya tenés cuenta? <a href="/login">Iniciá sesión</a></p>
</Card>

<style>
	h1 {
		margin: 0 0 var(--space-6) 0;
		font-size: var(--text-2xl);
		background: var(--gradient-brand);
		-webkit-background-clip: text;
		background-clip: text;
		color: transparent;
	}
	form {
		display: flex;
		flex-direction: column;
	}
	.hint {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin-top: var(--space-4);
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-4) 0;
	}
	a {
		color: var(--accent-primary);
	}
</style>
