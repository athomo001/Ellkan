<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-17 (pendiente #133): vuelta del proveedor de la organización. Fuera de
	// `(anon)` y `(app)` porque sirve a los dos casos: iniciar sesión y
	// vincular la cuenta ya abierta (`/settings/security`).
	//
	// 1. Quita `code` y `state` de la barra de direcciones (no quedan en el
	//    historial) y se los pasa al backend con `fetch`.
	// 2. Sesión completa: si la cuenta nació por SSO sin claves, el usuario
	//    elige su contraseña y el navegador genera las claves (una sola vez,
	//    `POST /me/keys/enroll`); si ya tiene claves, la bóveda pide la
	//    contraseña para abrirlas (SSO prueba quién es, no descifra nada).
	// 3. Con MFA pendiente, pide el código acá mismo.
	import { onMount } from 'svelte';
	import { get } from 'svelte/store';
	import { goto } from '$app/navigation';
	import Card from '#lib/components/Card.svelte';
	import Button from '#lib/components/Button.svelte';
	import TextField from '#lib/components/TextField.svelte';
	import { ssoApi, type ResultadoCallbackSso } from '#lib/api/sso';
	import { perfilApi } from '#lib/api/profile';
	import { verificarLoginTotp } from '#lib/crypto/totp';
	import { enrolarClaves } from '#lib/crypto/identity';
	import { sesion, clavesDesbloqueadas } from '#lib/state/session';
	import { ApiError } from '#lib/api/client';
	import { t } from '#lib/i18n';

	type Paso = 'cargando' | 'mfa' | 'enrolar' | 'vinculado' | 'configurar_mfa' | 'error';

	let paso = $state<Paso>('cargando');
	let error = $state<string | undefined>();
	let ocupado = $state(false);
	let codigo = $state('');
	let passphrase = $state('');
	let confirmacion = $state('');
	let email = $state('');

	function mensaje(err: unknown): string {
		return err instanceof ApiError || err instanceof Error ? err.message : get(t).sso.errorGenerico;
	}

	/** Sesión ya completa: identidad desde `/me` y, según tenga claves o no,
	 * enrolar o ir a la bóveda (que pide la contraseña para abrirlas). */
	async function continuarConSesion() {
		const perfil = await perfilApi.obtener();
		email = perfil.email;
		sesion.set({ sessionId: get(sesion).sessionId, userId: perfil.id, email: perfil.email });
		if (perfil.needs_key_enrollment) {
			paso = 'enrolar';
			return;
		}
		goto('/vault', { replaceState: true });
	}

	async function procesar(r: ResultadoCallbackSso) {
		switch (r.estado) {
			case 'vinculado':
				paso = 'vinculado';
				return;
			case 'completo':
				sesion.set({ sessionId: r.session_id, userId: null, email: null });
				await continuarConSesion();
				return;
			case 'pendiente_mfa':
				sesion.set({ sessionId: r.session_id, userId: null, email: null });
				paso = 'mfa';
				return;
			default:
				// Configurar MFA (o cambiar una contraseña provisoria) se hace en el
				// login con contraseña; esta sesión parcial no sirve para eso acá.
				sesion.set({ sessionId: null, userId: null, email: null });
				paso = 'configurar_mfa';
		}
	}

	onMount(async () => {
		const search = location.search;
		history.replaceState(history.state, '', location.pathname);
		if (!new URLSearchParams(search).has('code')) {
			error = get(t).sso.errorSinCodigo;
			paso = 'error';
			return;
		}
		try {
			await procesar(await ssoApi.callback(search));
		} catch (err) {
			error = mensaje(err);
			paso = 'error';
		}
	});

	async function enviarCodigo(e: SubmitEvent) {
		e.preventDefault();
		ocupado = true;
		error = undefined;
		try {
			await verificarLoginTotp(codigo.trim());
			await continuarConSesion();
		} catch (err) {
			error = mensaje(err);
		} finally {
			ocupado = false;
		}
	}

	async function enrolar(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;
		if (passphrase !== confirmacion) {
			error = get(t).sso.errorNoCoinciden;
			return;
		}
		if (passphrase.length < 12) {
			error = get(t).sso.errorCorta;
			return;
		}
		ocupado = true;
		try {
			clavesDesbloqueadas.set(await enrolarClaves(email, passphrase));
			// Cuenta nueva: sin kit de recuperación todavía.
			goto('/onboarding/recovery-kit', { replaceState: true });
		} catch (err) {
			// ELK-01 (#147): el servidor sólo acepta enrolar con la sesión que
			// emitió el callback SSO, y por 30 min: pasado eso, volver a entrar.
			error = err instanceof ApiError && err.status === 403 ? get(t).sso.errorSesionSsoVencida : mensaje(err);
		} finally {
			ocupado = false;
		}
	}
</script>

<svelte:head>
	<title>{$t.sso.titulo} — Ellkan</title>
</svelte:head>

<main>
	<Card>
		<h1>{$t.sso.titulo}</h1>

		{#if paso === 'cargando'}
			<p class="hint" role="status">{$t.sso.cargando}</p>
		{:else if paso === 'mfa'}
			<form onsubmit={enviarCodigo}>
				<p class="hint">{$t.sso.mfaHint}</p>
				<TextField label={$t.sso.codigo} bind:value={codigo} autocomplete="one-time-code" required />
				<Button type="submit" variant="primary" loading={ocupado}>{$t.sso.continuar}</Button>
			</form>
		{:else if paso === 'enrolar'}
			<form onsubmit={enrolar}>
				<p class="hint">{$t.sso.enrolarHint.replace('{email}', email)}</p>
				<TextField label={$t.sso.passphrase} type="password" bind:value={passphrase} autocomplete="new-password" required />
				<TextField label={$t.sso.confirmar} type="password" bind:value={confirmacion} autocomplete="new-password" required />
				<Button type="submit" variant="primary" loading={ocupado}>{$t.sso.crearClaves}</Button>
			</form>
		{:else if paso === 'vinculado'}
			<p>{$t.sso.vinculado}</p>
			<Button variant="primary" onclick={() => goto('/settings/security', { replaceState: true })}>{$t.sso.volver}</Button>
		{:else if paso === 'configurar_mfa'}
			<p>{$t.sso.configurarMfa}</p>
			<Button variant="primary" onclick={() => goto('/login', { replaceState: true })}>{$t.sso.irAlLogin}</Button>
		{:else}
			<Button variant="secondary" onclick={() => goto('/login', { replaceState: true })}>{$t.sso.irAlLogin}</Button>
		{/if}

		{#if error}
			<p class="error" role="alert">{error}</p>
		{/if}
	</Card>
</main>

<style>
	main {
		max-width: 28rem;
		margin: var(--space-8, 4rem) auto;
		padding: 0 var(--space-4);
	}
	h1 {
		margin: 0 0 var(--space-4) 0;
		font-size: var(--text-2xl);
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
		margin-top: var(--space-4);
	}
</style>
