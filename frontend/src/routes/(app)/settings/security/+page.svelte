<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-03: registrar una passkey nueva para este dispositivo/cuenta. Sin
	// PRF (ver nota en `$lib/crypto/passkeys.ts`) — reemplaza el paso HTTP
	// de login, la passphrase sigue haciendo falta para operaciones
	// criptográficas. No hay todavía un `GET /me/passkeys` en el backend
	// para listar/revocar las ya registradas — sólo alta, documentado como
	// gap real en `docs/pendientesVerificacionReal.md`.
	//
	// F-38: desbloqueo rápido local con TOTP — la passphrase que se tipea
	// acá para activar NUNCA se manda al servidor, sólo se usa localmente
	// para (a) confirmar que es la correcta (vía el mismo `/auth/key-material`
	// + `abrir_clave_privada` que usa el login real) y (b) envolverla con la
	// clave derivada del secreto TOTP local (`totp_envolver_passphrase`).
	import { onMount } from 'svelte';
	import { get } from 'svelte/store';
	import QRCode from 'qrcode';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import { registrarPasskey, listarPasskeys, revocarPasskey, type Passkey } from '$lib/crypto/passkeys';
	import { verificarPassphrase } from '$lib/crypto/identity';
	import { generarSetup, confirmarYActivar, estaActivo, desactivar } from '$lib/crypto/totp-local';
	import { accountRecoveryApi } from '$lib/api/accountRecovery';
	import { sellarMaterialParaOrg } from '$lib/crypto/accountRecovery';
	import { sesion, clavesDesbloqueadas } from '$lib/state/session';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let label = $state('');
	let passphrasePasskey = $state('');
	let registrando = $state(false);
	let error = $state<string | undefined>();
	let exito = $state(false);
	let passkeys = $state<Passkey[]>([]);

	async function cargarPasskeys() {
		try {
			passkeys = await listarPasskeys();
		} catch {
			/* la sección de arriba (alta) sigue funcionando igual si esto falla */
		}
	}
	onMount(cargarPasskeys);

	// F-16: estado de enrolamiento en Account Recovery — sin esto no hay
	// forma de saber si "Habilitar" ya se hizo antes en otro dispositivo.
	let recoveryEnrolada = $state(false);
	let cargandoRecovery = $state(true);
	let habilitandoRecovery = $state(false);
	let errorRecovery = $state<string | undefined>();
	onMount(async () => {
		try {
			recoveryEnrolada = (await accountRecoveryApi.miEstado()).enrolled;
		} catch {
			/* la sección simplemente no ofrece el botón si esto falla */
		} finally {
			cargandoRecovery = false;
		}
	});

	async function habilitarRecovery() {
		errorRecovery = undefined;
		const claves = get(clavesDesbloqueadas);
		if (!claves) {
			errorRecovery = get(t).settingsSecurity.recoveryClavesBloqueadas;
			return;
		}
		habilitandoRecovery = true;
		try {
			const org = await accountRecoveryApi.orgPublicKey();
			const sellado = await sellarMaterialParaOrg(org.public_key_x25519_b64, claves);
			await accountRecoveryApi.enrolar(sellado);
			recoveryEnrolada = true;
		} catch (err) {
			errorRecovery = err instanceof ApiError ? err.message : get(t).settingsSecurity.recoveryErrorHabilitar;
		} finally {
			habilitandoRecovery = false;
		}
	}

	async function agregar(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;
		exito = false;
		registrando = true;
		try {
			await registrarPasskey($sesion.email ?? '', passphrasePasskey, label || undefined);
			exito = true;
			label = '';
			passphrasePasskey = '';
			await cargarPasskeys();
		} catch (err) {
			error = err instanceof ApiError ? err.message : get(t).settingsSecurity.errorPasskey;
		} finally {
			registrando = false;
		}
	}

	let revocandoId = $state<string | undefined>();
	async function revocarPasskeyPropia(id: string) {
		revocandoId = id;
		try {
			await revocarPasskey(id);
			await cargarPasskeys();
		} catch {
			/* sin feedback dedicado — la fila simplemente no desaparece, el usuario reintenta */
		} finally {
			revocandoId = undefined;
		}
	}

	const email = $derived($sesion.email ?? '');
	let activo = $state(false);
	$effect(() => {
		activo = email ? estaActivo(email) : false;
	});

	let pasoSetup = $state<'inicial' | 'passphrase' | 'qr'>('inicial');
	let passphraseSetup = $state('');
	let secretoPendiente: Uint8Array | undefined;
	let otpauthUri = $state<string | undefined>();
	let qrDataUrl = $state<string | undefined>();
	let secretoBase32Mostrado = $state<string | undefined>();
	let codigoSetup = $state('');
	let cargandoSetup = $state(false);
	let errorSetup = $state<string | undefined>();

	function empezarSetup() {
		pasoSetup = 'passphrase';
		errorSetup = undefined;
	}

	async function confirmarPassphrase(e: SubmitEvent) {
		e.preventDefault();
		errorSetup = undefined;
		cargandoSetup = true;
		try {
			await verificarPassphrase(email, passphraseSetup);
			const { secreto, otpauthUri: uri } = await generarSetup(email);
			secretoPendiente = secreto;
			otpauthUri = uri;
			qrDataUrl = await QRCode.toDataURL(uri);
			const params = new URLSearchParams(uri.split('?')[1]);
			secretoBase32Mostrado = params.get('secret') ?? undefined;
			pasoSetup = 'qr';
		} catch (err) {
			errorSetup =
				err instanceof ApiError || err instanceof Error ? err.message : get(t).settingsSecurity.errorPassphraseIncorrecta;
		} finally {
			cargandoSetup = false;
		}
	}

	async function confirmarCodigoSetup(e: SubmitEvent) {
		e.preventDefault();
		if (!secretoPendiente) return;
		errorSetup = undefined;
		cargandoSetup = true;
		try {
			await confirmarYActivar(email, secretoPendiente, codigoSetup, passphraseSetup);
			activo = true;
			pasoSetup = 'inicial';
			passphraseSetup = '';
			codigoSetup = '';
			secretoPendiente = undefined;
		} catch (err) {
			errorSetup = err instanceof Error ? err.message : get(t).settingsSecurity.errorCodigoIncorrecto;
		} finally {
			cargandoSetup = false;
		}
	}

	function revocar() {
		desactivar(email);
		activo = false;
		pasoSetup = 'inicial';
	}
</script>

<svelte:head>
	<title>{$t.settingsSecurity.titulo} — Ellkan</title>
</svelte:head>

<h1>{$t.settingsSecurity.titulo}</h1>

<Card>
	<h2>{$t.settingsSecurity.passkeysTitulo}</h2>
	<p class="hint">{$t.settingsSecurity.passkeysHint}</p>
	<form onsubmit={agregar}>
		<TextField label={$t.settingsSecurity.nombreOpcional} bind:value={label} hint={$t.settingsSecurity.nombreHint} />
		<TextField
			label={$t.settingsSecurity.passphraseActual}
			type="password"
			bind:value={passphrasePasskey}
			autocomplete="current-password"
			hint={$t.settingsSecurity.passphrasePrfHint}
			required
		/>
		{#if error}<p class="error">{error}</p>{/if}
		{#if exito}<p class="ok">{$t.settingsSecurity.passkeyRegistrada}</p>{/if}
		<Button type="submit" variant="primary" loading={registrando}>{$t.settingsSecurity.agregarPasskey}</Button>
	</form>

	{#if passkeys.length > 0}
		<ul class="lista-passkeys">
			{#each passkeys as passkey (passkey.id)}
				<li class="item-passkey">
					<div class="info">
						<strong>{passkey.label || $t.settingsSecurity.sinNombre}</strong>
						{#if passkey.tienePrf}<span class="badge-prf">{$t.settingsSecurity.desbloqueoAutomatico}</span>{/if}
					</div>
					<Button variant="danger" onclick={() => revocarPasskeyPropia(passkey.id)} loading={revocandoId === passkey.id}>
						{$t.settingsSecurity.revocarPasskey}
					</Button>
				</li>
			{/each}
		</ul>
	{/if}
</Card>

<Card>
	<h2>{$t.settingsSecurity.desbloqueoTitulo}</h2>
	<p class="hint">{$t.settingsSecurity.desbloqueoHint}</p>

	{#if activo}
		<p class="ok">{$t.settingsSecurity.activoEnDispositivo}</p>
		<Button variant="danger" onclick={revocar}>{$t.settingsSecurity.desactivar}</Button>
	{:else if pasoSetup === 'inicial'}
		<Button variant="secondary" onclick={empezarSetup}>{$t.settingsSecurity.activarEnDispositivo}</Button>
	{:else if pasoSetup === 'passphrase'}
		<form onsubmit={confirmarPassphrase}>
			<TextField
				label={$t.settingsSecurity.passphraseActual}
				type="password"
				bind:value={passphraseSetup}
				autocomplete="current-password"
				required
			/>
			{#if errorSetup}<p class="error">{errorSetup}</p>{/if}
			<Button type="submit" variant="primary" loading={cargandoSetup}>{$t.settingsSecurity.continuar}</Button>
		</form>
	{:else if pasoSetup === 'qr'}
		{#if qrDataUrl}
			<img class="qr" src={qrDataUrl} alt={$t.settingsSecurity.qrAlt} width="200" height="200" />
		{/if}
		{#if secretoBase32Mostrado}
			<p class="secreto">
				{$t.settingsSecurity.sinCamaraHint} <code>{secretoBase32Mostrado}</code>
			</p>
		{/if}
		<form onsubmit={confirmarCodigoSetup}>
			<TextField
				label={$t.settingsSecurity.codigoApp}
				bind:value={codigoSetup}
				autocomplete="one-time-code"
				required
			/>
			{#if errorSetup}<p class="error">{errorSetup}</p>{/if}
			<Button type="submit" variant="primary" loading={cargandoSetup}>{$t.settingsSecurity.activar}</Button>
		</form>
	{/if}
</Card>

<Card>
	<h2>{$t.settingsSecurity.recoveryTitulo}</h2>
	<p class="hint">{$t.settingsSecurity.recoveryHint}</p>

	{#if cargandoRecovery}
		<p class="hint">{$t.settingsSecurity.cargando}</p>
	{:else if recoveryEnrolada}
		<p class="ok">{$t.settingsSecurity.recoveryHabilitada}</p>
	{:else}
		{#if errorRecovery}<p class="error">{errorRecovery}</p>{/if}
		<Button variant="secondary" onclick={habilitarRecovery} loading={habilitandoRecovery}>
			{$t.settingsSecurity.recoveryHabilitar}
		</Button>
	{/if}
</Card>

<style>
	h1 {
		margin: 0 0 var(--space-6) 0;
		font-size: var(--text-2xl);
		color: var(--text-primary);
	}
	h2 {
		margin: 0 0 var(--space-2) 0;
		font-size: var(--text-lg);
		color: var(--text-primary);
	}
	form {
		display: flex;
		flex-direction: column;
		max-width: 24rem;
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
		margin: 0 0 var(--space-4) 0;
	}
	:global(.card) + :global(.card) {
		margin-top: var(--space-4);
	}
	.lista-passkeys {
		list-style: none;
		margin: var(--space-4) 0 0 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.item-passkey {
		display: flex;
		align-items: center;
		justify-content: space-between;
		gap: var(--space-3);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
	}
	.info {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.badge-prf {
		font-size: var(--text-xs);
		color: var(--success);
		border: 1px solid var(--success);
		border-radius: var(--radius-sm);
		padding: 0 var(--space-2);
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
