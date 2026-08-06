<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-01/F-02/F-38: primera pantalla real donde corre
	// Argon2id→HKDF→AEAD en un navegador de verdad. Maneja los cuatro
	// estados posibles de `iniciarSesion` (auth::dto::VerifyResponse) —
	// MFA (F-14) queda con mensaje explícito, pantalla dedicada pendiente
	// (checklist F-38 aparte).
	import { goto } from '$app/navigation';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import Card from '$lib/components/Card.svelte';
	import { iniciarSesion, verificarDispositivo } from '$lib/crypto/identity';
	import { sesion, clavesDesbloqueadas } from '$lib/state/session';
	import { ApiError } from '$lib/api/client';

	let email = $state('');
	let passphrase = $state('');
	let cargando = $state(false);
	let error = $state<string | undefined>();

	// F-02: sólo se llena si el backend responde "pendiente_dispositivo".
	let deviceChallengeId = $state<string | undefined>();
	let codigoDispositivo = $state('');
	let verificandoDispositivo = $state(false);

	let mfaPendiente = $state(false);

	function completarSesion(userId: string | undefined, sessionId: string | undefined) {
		sesion.set({ sessionId: sessionId ?? null, userId: userId ?? null, email });
		goto('/vault');
	}

	async function enviar(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;
		cargando = true;
		try {
			const resultado = await iniciarSesion(email, passphrase);
			switch (resultado.estado) {
				case 'completo':
					if (resultado.claves) clavesDesbloqueadas.set(resultado.claves);
					completarSesion(resultado.userId, resultado.sessionId);
					break;
				case 'pendiente_dispositivo':
					deviceChallengeId = resultado.deviceChallengeId;
					if (resultado.claves) clavesDesbloqueadas.set(resultado.claves);
					break;
				case 'pendiente_mfa':
				case 'requiere_configurar_mfa':
					// Sesión parcial: queda como Bearer para el próximo paso
					// (POST /auth/mfa/verify o /me/mfa/totp/setup) una vez
					// exista esa pantalla dedicada.
					sesion.set({ sessionId: resultado.sessionId ?? null, userId: null, email });
					mfaPendiente = true;
					break;
			}
		} catch (err) {
			error = err instanceof ApiError ? err.message : 'No se pudo iniciar sesión.';
		} finally {
			cargando = false;
		}
	}

	async function confirmarDispositivo(e: SubmitEvent) {
		e.preventDefault();
		if (!deviceChallengeId) return;
		error = undefined;
		verificandoDispositivo = true;
		try {
			const resultado = await verificarDispositivo(deviceChallengeId, codigoDispositivo);
			if (resultado.estado === 'completo') {
				completarSesion(resultado.userId, resultado.sessionId);
			} else {
				error = 'Código incorrecto o vencido.';
			}
		} catch (err) {
			error = err instanceof ApiError ? err.message : 'No se pudo verificar el dispositivo.';
		} finally {
			verificandoDispositivo = false;
		}
	}
</script>

<svelte:head>
	<title>Iniciar sesión — Ellkan</title>
</svelte:head>

<Card>
	<h1>Ellkan</h1>

	{#if mfaPendiente}
		<p class="hint">
			Esta cuenta requiere un segundo factor. La pantalla de verificación TOTP todavía no está
			implementada en este cliente — pedila desde otro cliente ya soportado.
		</p>
	{:else if deviceChallengeId}
		<p class="hint">Te enviamos un código a tu email para reconocer este dispositivo.</p>
		<form onsubmit={confirmarDispositivo}>
			<TextField
				label="Código de verificación"
				bind:value={codigoDispositivo}
				autocomplete="one-time-code"
				required
			/>
			{#if error}<p class="error">{error}</p>{/if}
			<Button type="submit" variant="primary" loading={verificandoDispositivo}>Verificar</Button>
		</form>
	{:else}
		<form onsubmit={enviar}>
			<TextField label="Email" type="email" bind:value={email} autocomplete="email" required />
			<TextField
				label="Passphrase"
				type="password"
				bind:value={passphrase}
				autocomplete="current-password"
				required
			/>
			{#if error}<p class="error">{error}</p>{/if}
			<Button type="submit" variant="primary" loading={cargando}>Iniciar sesión</Button>
		</form>
		<p class="hint">¿No tenés cuenta? <a href="/register">Registrate</a></p>
	{/if}
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
