<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-16: Account Recovery self-service — sin sesión a propósito (ver
	// `account_recovery::handlers`), cubre justo el caso de alguien que
	// perdió la passphrase. Tres pasos: pedir por email, esperar aprobación
	// (poll), fijar una passphrase nueva. `requestId` sólo vive en memoria
	// del componente — un F5 pierde el estado y hay que reintentar, flujo
	// raro, aceptable.
	import { goto } from '$app/navigation';
	import { onDestroy } from 'svelte';
	import { get } from 'svelte/store';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import Card from '$lib/components/Card.svelte';
	import { accountRecoveryApi } from '$lib/api/accountRecovery';
	import { generarClaveEfimera, desellarMaterialDelEscrow, reSellarConNuevaPassphrase } from '$lib/crypto/accountRecovery';
	import { evaluarFortaleza } from '$lib/crypto/passwordStrength';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	type Paso = 'email' | 'esperando' | 'passphrase' | 'lista';
	let paso = $state<Paso>('email');
	let email = $state('');
	let cargando = $state(false);
	let error = $state<string | undefined>();

	let requestId: string | undefined;
	let efimeraPrivada: Uint8Array | undefined;
	let intervalo: ReturnType<typeof setInterval> | undefined;

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

	function detenerPoll() {
		if (intervalo) clearInterval(intervalo);
		intervalo = undefined;
	}
	onDestroy(detenerPoll);

	async function pedirRecuperacion(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;
		cargando = true;
		try {
			const efimera = await generarClaveEfimera();
			efimeraPrivada = efimera.privada;
			const solicitud = await accountRecoveryApi.crearSolicitud(email, efimera.publicaB64);
			requestId = solicitud.id;
			paso = 'esperando';
			intervalo = setInterval(async () => {
				if (!requestId) return;
				try {
					const actual = await accountRecoveryApi.estadoSolicitud(requestId);
					if (actual.status === 'approved') {
						detenerPoll();
						paso = 'passphrase';
					}
				} catch {
					/* red intermitente: el próximo tick reintenta solo */
				}
			}, 5000);
		} catch (err) {
			error = err instanceof ApiError ? err.message : get(t).recuperacionCuenta.errorGenerico;
		} finally {
			cargando = false;
		}
	}

	async function fijarPassphraseNueva(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;

		if (passphraseNueva !== passphraseConfirmar) {
			error = get(t).recuperacionCuenta.errorNoCoinciden;
			return;
		}
		if (!requestId || !efimeraPrivada) return;

		cargando = true;
		try {
			const estado = await accountRecoveryApi.estadoSolicitud(requestId);
			if (!estado.sealed_private_key_for_requester_b64) {
				throw new Error(get(t).recuperacionCuenta.errorGenerico);
			}
			const material = await desellarMaterialDelEscrow(efimeraPrivada, estado.sealed_private_key_for_requester_b64);
			const blob = await reSellarConNuevaPassphrase(email, passphraseNueva, material);
			await accountRecoveryApi.completar(requestId, blob.blobB64, blob.nonceB64, blob.saltB64);
			paso = 'lista';
		} catch (err) {
			error = err instanceof ApiError || err instanceof Error ? err.message : get(t).recuperacionCuenta.errorGenerico;
		} finally {
			cargando = false;
		}
	}
</script>

<svelte:head>
	<title>{$t.recuperacionCuenta.titulo}</title>
</svelte:head>

<Card>
	<h1>{$t.recuperacionCuenta.titulo}</h1>

	{#if paso === 'email'}
		<p class="subtitulo">{$t.recuperacionCuenta.subtitulo}</p>
		<form onsubmit={pedirRecuperacion}>
			<TextField label={$t.recuperacionCuenta.email} type="email" bind:value={email} autocomplete="email" required />
			{#if error}<p class="error">{error}</p>{/if}
			<Button type="submit" variant="primary" loading={cargando}>{$t.recuperacionCuenta.solicitar}</Button>
		</form>
	{:else if paso === 'esperando'}
		<p class="hint">{$t.recuperacionCuenta.esperandoAprobacion}</p>
	{:else if paso === 'passphrase'}
		<p class="hint">{$t.recuperacionCuenta.aprobadaHint}</p>
		<form onsubmit={fijarPassphraseNueva}>
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
