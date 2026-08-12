<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// Recovery kit: flujo primario de recuperación de cuenta, self-service,
	// sin admin de por medio — distinto de F-16 (movido a
	// `/recover/admin-approval`, fallback para quien no tiene kit). Pedido
	// por email → link con token → nueva passphrase + kit → todo client-side
	// hasta que ambos pasos cierran → segundo factor (TOTP si el usuario lo
	// tiene confirmado, email si no) → listo. Si la URL trae `?token=`, se
	// salta directo al paso de kit+passphrase tras verificar el token.
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import { onMount } from 'svelte';
	import { get } from 'svelte/store';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import Card from '$lib/components/Card.svelte';
	import { recoveryKitApi } from '$lib/api/recoveryKit';
	import { desellarMaterialDelEscrow, reSellarConNuevaPassphrase } from '$lib/crypto/accountRecovery';
	import { base64ABytes } from '$lib/crypto/b64';
	import { evaluarFortaleza } from '$lib/crypto/passwordStrength';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	type Paso = 'email' | 'esperando-email' | 'kit-y-passphrase' | 'mfa' | 'lista';
	let paso = $state<Paso>('email');
	let email = $state('');
	let cargando = $state(false);
	let error = $state<string | undefined>();

	const token = page.url.searchParams.get('token') ?? undefined;
	let selladoMaterialB64: string | undefined;
	let mfaMethod = $state<'totp' | 'email' | undefined>(undefined);

	let kitPrivadaB64 = $state('');
	let passphraseNueva = $state('');
	let passphraseConfirmar = $state('');
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

	let blobListo: { blobB64: string; nonceB64: string; saltB64: string } | undefined;
	let codigoMfa = $state('');

	onMount(async () => {
		if (!token) return;
		cargando = true;
		try {
			const verificado = await recoveryKitApi.verificarToken(token);
			selladoMaterialB64 = verificado.sealed_identity_material_b64;
			mfaMethod = verificado.mfa_method;
			email = verificado.email;
			paso = 'kit-y-passphrase';
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.recoveryKit.errorTokenInvalido;
		} finally {
			cargando = false;
		}
	});

	async function pedirLink(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;
		cargando = true;
		try {
			await recoveryKitApi.solicitarReset(email);
			paso = 'esperando-email';
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.recoveryKit.errorGenerico;
		} finally {
			cargando = false;
		}
	}

	async function confirmarKitYPassphrase(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;

		if (passphraseNueva !== passphraseConfirmar) {
			error = $t.recoveryKit.errorNoCoinciden;
			return;
		}
		if (!selladoMaterialB64) return;

		cargando = true;
		try {
			const kitPrivada = base64ABytes(kitPrivadaB64.trim());
			const material = await desellarMaterialDelEscrow(kitPrivada, selladoMaterialB64);
			blobListo = await reSellarConNuevaPassphrase(email, passphraseNueva, material);

			if (mfaMethod === 'email' && token) {
				await recoveryKitApi.enviarCodigoEmail(token);
			}
			paso = 'mfa';
		} catch {
			error = $t.recoveryKit.errorKitInvalido;
		} finally {
			cargando = false;
		}
	}

	async function confirmarMfa(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;
		if (!token || !blobListo) return;

		cargando = true;
		try {
			await recoveryKitApi.completar(token, codigoMfa, blobListo.blobB64, blobListo.nonceB64, blobListo.saltB64);
			paso = 'lista';
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.recoveryKit.errorGenerico;
		} finally {
			cargando = false;
		}
	}
</script>

<svelte:head>
	<title>{$t.recoveryKit.tituloRecover} — Ellkan</title>
</svelte:head>

<Card>
	<h1>{$t.recoveryKit.tituloRecover}</h1>

	{#if paso === 'email'}
		<p class="subtitulo">{$t.recoveryKit.subtituloRecover}</p>
		<form onsubmit={pedirLink}>
			<TextField label={$t.recuperacionCuenta.email} type="email" bind:value={email} autocomplete="email" required />
			{#if error}<p class="error">{error}</p>{/if}
			<Button type="submit" variant="primary" loading={cargando}>{$t.recoveryKit.pedirLink}</Button>
		</form>
		<p class="hint centrado"><a href="/recover/admin-approval">{$t.recoveryKit.sinKitLink}</a></p>
	{:else if paso === 'esperando-email'}
		<p class="hint">{$t.recoveryKit.esperandoEmailHint}</p>
	{:else if paso === 'kit-y-passphrase'}
		<p class="hint">{$t.recoveryKit.kitYPassphraseHint}</p>
		<form onsubmit={confirmarKitYPassphrase}>
			<TextField
				label={$t.recoveryKit.pegarKit}
				bind:value={kitPrivadaB64}
				hint={$t.recoveryKit.pegarKitHint}
				required
			/>
			<TextField
				label={$t.recuperacionCuenta.passphraseNueva}
				type="password"
				bind:value={passphraseNueva}
				autocomplete="new-password"
				required
			/>
			{#if passphraseNueva}
				<p class="fortaleza fortaleza-{fortaleza.score}">{labelFortaleza}</p>
			{/if}
			<TextField
				label={$t.recuperacionCuenta.passphraseConfirmar}
				type="password"
				bind:value={passphraseConfirmar}
				autocomplete="new-password"
				required
			/>
			{#if error}<p class="error">{error}</p>{/if}
			<Button type="submit" variant="primary" loading={cargando}>{$t.recoveryKit.continuar}</Button>
		</form>
	{:else if paso === 'mfa'}
		<p class="hint">
			{mfaMethod === 'totp' ? $t.recoveryKit.mfaTotpHint : $t.recoveryKit.mfaEmailHint}
		</p>
		<form onsubmit={confirmarMfa}>
			<TextField label={$t.login.codigoApp} bind:value={codigoMfa} autocomplete="one-time-code" required />
			{#if error}<p class="error">{error}</p>{/if}
			<Button type="submit" variant="primary" loading={cargando}>{$t.recuperacionCuenta.fijarPassphrase}</Button>
		</form>
	{:else if paso === 'lista'}
		<p class="ok">{$t.recuperacionCuenta.completaHint}</p>
		<Button variant="primary" onclick={() => goto('/login')}>{$t.recuperacionCuenta.irALogin}</Button>
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
	.hint {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin: var(--space-2) 0 var(--space-4) 0;
	}
	.hint.centrado {
		text-align: center;
		margin-top: var(--space-4);
	}
	form {
		display: flex;
		flex-direction: column;
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-4) 0;
	}
	.ok {
		color: var(--success);
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
</style>
