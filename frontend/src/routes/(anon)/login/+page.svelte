<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-01/F-02/F-38: primera pantalla real donde corre
	// Argon2id→HKDF→AEAD en un navegador de verdad. Maneja los cinco
	// estados posibles de `iniciarSesion` (auth::dto::VerifyResponse),
	// incluidos los dos de MFA (F-14): "pendiente_mfa" (ya tiene TOTP
	// configurado, sólo falta el código) y "requiere_configurar_mfa" (la
	// política lo exige y todavía no tiene ningún segundo factor — setup +
	// confirmación en el mismo flujo, `MfaService::confirmar_setup_totp`
	// completa la sesión al confirmar, sin un `/auth/mfa/verify` aparte).
	import { goto } from '$app/navigation';
	import { get } from 'svelte/store';
	import QRCode from 'qrcode';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import Card from '$lib/components/Card.svelte';
	import { iniciarSesion, verificarDispositivo } from '$lib/crypto/identity';
	import { iniciarSetupTotp, confirmarSetupTotp, verificarLoginTotp } from '$lib/crypto/totp';
	import { iniciarSesionConPasskey } from '$lib/crypto/passkeys';
	import { desbloquear as desbloquearLocal } from '$lib/crypto/totp-local';
	import { sesion, clavesDesbloqueadas } from '$lib/state/session';
	import { obtenerTokenSeguridad, COLOR_HEX } from '$lib/state/securityToken';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let email = $state('');
	let passphrase = $state('');
	// F-01: token de seguridad — nada si nunca se generó uno para este email
	// en este navegador (dispositivo nuevo, estado esperado, no un error).
	const tokenSeguridad = $derived(email ? obtenerTokenSeguridad(email) : null);
	let cargando = $state(false);
	let error = $state<string | undefined>();

	// F-03: alternativa sin passphrase — no desbloquea la clave privada
	// (sin PRF todavía, ver `$lib/crypto/passkeys.ts`), sólo reemplaza el
	// paso HTTP de login.
	let conPasskey = $state(false);
	let cargandoPasskey = $state(false);

	// F-38: código local en vez de tipear la passphrase — recupera la
	// passphrase real (localmente, sin red) y sigue el login normal con
	// ella, nunca se salta ningún paso del flujo real.
	let conCodigoLocal = $state(false);
	let codigoLocal = $state('');
	let cargandoLocal = $state(false);

	// F-02: sólo se llena si el backend responde "pendiente_dispositivo".
	let deviceChallengeId = $state<string | undefined>();
	let codigoDispositivo = $state('');
	let verificandoDispositivo = $state(false);

	// F-14: MFA de login ya configurado, sólo falta verificar el código.
	let mfaPendiente = $state(false);
	let codigoMfa = $state('');
	let verificandoMfa = $state(false);

	// F-14: MFA de login todavía sin configurar, la política lo exige.
	let mfaSetupPendiente = $state(false);
	let qrDataUrl = $state<string | undefined>();
	let secretoTotp = $state<string | undefined>();
	let codigoSetup = $state('');
	let confirmandoSetup = $state(false);
	let cargandoSetup = $state(true);

	function completarSesion(userId: string | undefined, sessionId: string | undefined) {
		sesion.set({ sessionId: sessionId ?? null, userId: userId ?? null, email });
		goto('/vault');
	}

	async function procesarResultadoLogin(resultado: Awaited<ReturnType<typeof iniciarSesion>>) {
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
				// Sesión parcial: queda como Bearer para POST /auth/mfa/verify.
				// `resultado.claves` ya se calculó (abrir_clave_privada corre
				// antes del chequeo de estado en `iniciarSesion`) — guardarlo
				// acá evita que el Vault se quede sin clave privada después de
				// completar el segundo factor, sin volver a pedir la passphrase.
				sesion.set({ sessionId: resultado.sessionId ?? null, userId: null, email });
				if (resultado.claves) clavesDesbloqueadas.set(resultado.claves);
				mfaPendiente = true;
				break;
			case 'requiere_configurar_mfa':
				// Sesión parcial: queda como Bearer para POST
				// /me/mfa/totp/{setup,confirm}.
				sesion.set({ sessionId: resultado.sessionId ?? null, userId: null, email });
				if (resultado.claves) clavesDesbloqueadas.set(resultado.claves);
				mfaSetupPendiente = true;
				await cargarSetupTotp();
				break;
		}
	}

	async function enviar(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;
		cargando = true;
		try {
			await procesarResultadoLogin(await iniciarSesion(email, passphrase));
		} catch (err) {
			error = err instanceof ApiError ? err.message : get(t).login.errorGenerico;
		} finally {
			cargando = false;
		}
	}

	async function enviarConCodigoLocal(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;
		cargandoLocal = true;
		try {
			const passphraseRecuperada = await desbloquearLocal(email, codigoLocal);
			await procesarResultadoLogin(await iniciarSesion(email, passphraseRecuperada));
		} catch (err) {
			error = err instanceof ApiError || err instanceof Error ? err.message : get(t).login.errorDesbloqueoLocal;
		} finally {
			cargandoLocal = false;
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
				error = get(t).login.errorCodigoIncorrectoOVencido;
			}
		} catch (err) {
			error = err instanceof ApiError ? err.message : get(t).login.errorVerificarDispositivo;
		} finally {
			verificandoDispositivo = false;
		}
	}

	async function confirmarMfa(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;
		verificandoMfa = true;
		try {
			await verificarLoginTotp(codigoMfa);
			// `sesion.sessionId` ya está seteado desde `enviar()` — el
			// backend acaba de marcar `mfa_verified_at` sobre esa misma sesión.
			completarSesion(undefined, get(sesion).sessionId ?? undefined);
		} catch (err) {
			error = err instanceof ApiError ? err.message : get(t).login.errorCodigoIncorrecto;
		} finally {
			verificandoMfa = false;
		}
	}

	async function cargarSetupTotp() {
		cargandoSetup = true;
		error = undefined;
		try {
			const { secretBase32, otpauthUri } = await iniciarSetupTotp();
			secretoTotp = secretBase32;
			qrDataUrl = await QRCode.toDataURL(otpauthUri);
		} catch (err) {
			error = err instanceof ApiError ? err.message : get(t).login.errorSetupMfa;
		} finally {
			cargandoSetup = false;
		}
	}

	async function confirmarSetup(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;
		confirmandoSetup = true;
		try {
			await confirmarSetupTotp(codigoSetup);
			completarSesion(undefined, get(sesion).sessionId ?? undefined);
		} catch (err) {
			error = err instanceof ApiError ? err.message : get(t).login.errorCodigoIncorrecto;
		} finally {
			confirmandoSetup = false;
		}
	}

	async function enviarConPasskey(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;
		cargandoPasskey = true;
		try {
			const resultado = await iniciarSesionConPasskey(email);
			if (resultado.claves) clavesDesbloqueadas.set(resultado.claves);
			completarSesion(resultado.userId, resultado.sessionId);
		} catch (err) {
			error = err instanceof ApiError ? err.message : get(t).login.errorPasskey;
		} finally {
			cargandoPasskey = false;
		}
	}
</script>

<svelte:head>
	<title>{$t.login.titulo}</title>
</svelte:head>

<Card>
	<h1>{$t.login.iniciarSesion}</h1>

	{#if mfaSetupPendiente}
		<p class="hint">{$t.login.mfaSetupHint}</p>
		{#if cargandoSetup}
			<p class="hint">{$t.login.generandoCodigo}</p>
		{:else}
			{#if qrDataUrl}
				<img class="qr" src={qrDataUrl} alt={$t.login.qrAlt} width="200" height="200" />
			{/if}
			{#if secretoTotp}
				<p class="secreto">
					{$t.login.sinCamaraHint} <code>{secretoTotp}</code>
				</p>
			{/if}
			<form onsubmit={confirmarSetup}>
				<TextField label={$t.login.codigoApp} bind:value={codigoSetup} autocomplete="one-time-code" required />
				{#if error}<p class="error">{error}</p>{/if}
				<Button type="submit" variant="primary" loading={confirmandoSetup}>{$t.login.confirmar}</Button>
			</form>
		{/if}
	{:else if mfaPendiente}
		<p class="hint">{$t.login.mfaPendienteHint}</p>
		<form onsubmit={confirmarMfa}>
			<TextField label={$t.login.codigoApp} bind:value={codigoMfa} autocomplete="one-time-code" required />
			{#if error}<p class="error">{error}</p>{/if}
			<Button type="submit" variant="primary" loading={verificandoMfa}>{$t.login.verificar}</Button>
		</form>
	{:else if deviceChallengeId}
		<p class="hint">{$t.login.verificarDispositivoHint}</p>
		<form onsubmit={confirmarDispositivo}>
			<TextField
				label={$t.login.codigoVerificacionDispositivo}
				bind:value={codigoDispositivo}
				autocomplete="one-time-code"
				required
			/>
			{#if error}<p class="error">{error}</p>{/if}
			<Button type="submit" variant="primary" loading={verificandoDispositivo}>{$t.login.verificar}</Button>
		</form>
	{:else if conPasskey}
		<form onsubmit={enviarConPasskey}>
			<TextField label={$t.login.email} type="email" bind:value={email} autocomplete="email" required />
			{#if error}<p class="error">{error}</p>{/if}
			<Button type="submit" variant="primary" loading={cargandoPasskey}>{$t.login.continuarConPasskey}</Button>
		</form>
		<p class="hint">
			<button type="button" class="link" onclick={() => (conPasskey = false)}>{$t.login.usarPassphrase}</button>
		</p>
	{:else if conCodigoLocal}
		<form onsubmit={enviarConCodigoLocal}>
			<TextField label={$t.login.email} type="email" bind:value={email} autocomplete="email" required />
			<TextField label={$t.login.codigoLocal} bind:value={codigoLocal} autocomplete="one-time-code" required />
			{#if error}<p class="error">{error}</p>{/if}
			<Button type="submit" variant="primary" loading={cargandoLocal}>{$t.login.desbloquear}</Button>
		</form>
		<p class="hint">
			<button type="button" class="link" onclick={() => (conCodigoLocal = false)}>{$t.login.usarPassphrase}</button
			>
		</p>
	{:else}
		<p class="subtitulo">{$t.login.subtitulo}</p>
		<form onsubmit={enviar}>
			<TextField label={$t.login.email} type="email" bind:value={email} autocomplete="email" required />
			{#if tokenSeguridad}
				<p class="token-seguridad">
					<span class="punto-token" style:background={COLOR_HEX[tokenSeguridad.color]}></span>
					{$t.login.tokenSeguridadHint} <strong>{tokenSeguridad.palabra}</strong>
				</p>
			{/if}
			<TextField
				label={$t.login.passphrase}
				type="password"
				bind:value={passphrase}
				autocomplete="current-password"
				required
			/>
			{#if error}<p class="error">{error}</p>{/if}
			<Button type="submit" variant="primary" loading={cargando}>{$t.login.iniciarSesion}</Button>
		</form>
		<p class="hint centrado">{$t.login.sinCuenta} <a href="/register">{$t.login.registrate}</a></p>
		<hr />
		<p class="hint centrado">
			<button type="button" class="link" onclick={() => (conPasskey = true)}>{$t.login.usarPasskey}</button>
			· <button type="button" class="link" onclick={() => (conCodigoLocal = true)}>{$t.login.usarCodigoLocal}</button
			>
		</p>
	{/if}
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
	hr {
		border: none;
		border-top: 1px solid var(--border-color);
		margin: var(--space-4) 0;
	}
	.hint {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin-top: var(--space-4);
	}
	.hint.centrado {
		text-align: center;
		margin-top: 0;
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-4) 0;
	}
	.token-seguridad {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0 0 var(--space-4) 0;
	}
	.punto-token {
		display: inline-block;
		width: 0.9rem;
		height: 0.9rem;
		border-radius: 50%;
		border: 1px solid var(--border-color);
		flex: 0 0 auto;
	}
	.link {
		background: none;
		border: none;
		padding: 0;
		font: inherit;
		color: var(--accent-primary);
		cursor: pointer;
	}
	a {
		color: var(--accent-primary);
	}
	.qr {
		display: block;
		margin: var(--space-4) auto;
		border-radius: var(--radius-sm);
		background: #fff;
		padding: var(--space-2);
	}
	.secreto {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		text-align: center;
		margin: 0 0 var(--space-4) 0;
	}
	.secreto code {
		font-family: var(--font-mono);
		color: var(--text-primary);
		word-break: break-all;
	}
</style>
