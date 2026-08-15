<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-26: página pública de destinatario externo — sin login, a
	// propósito (spec `03-api-contrato.md`, único endpoint sin sesión de
	// toda la API). Sirve el mismo `ellkan_crypto.wasm` que el resto del
	// frontend (`(anon)` layout ya no tiene nav ni bundle de admin) y
	// descifra 100% client-side con la clave del fragmento de la URL, que
	// el navegador nunca envía al servidor.
	import { onMount } from 'svelte';
	import { page } from '$app/state';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import SecretField from '$lib/components/SecretField.svelte';
	import { externalSharesApi } from '$lib/api/externalShares';
	import { claveFragmentoDeUrl, descifrarContenidoDeShare } from '$lib/crypto/externalShare';
	import { ApiError } from '$lib/api/client';
	import { t } from '$lib/i18n';

	let cargando = $state(true);
	let error = $state<string | undefined>();
	let necesitaPassphrase = $state(false);
	let errorPassphrase = $state<string | undefined>();
	let contenido = $state<string | undefined>();
	let passphrase = $state('');
	let desbloqueando = $state(false);

	let ciphertextB64: string | undefined;
	let passwordSaltB64: string | null = null;
	let claveFragmento: string | null = null;

	async function cargar() {
		const id = page.params.id;
		if (!id) {
			error = $t.externalShare.noDisponible;
			cargando = false;
			return;
		}
		claveFragmento = claveFragmentoDeUrl();
		if (!claveFragmento) {
			error = $t.externalShare.sinClave;
			cargando = false;
			return;
		}

		try {
			const cuerpo = await externalSharesApi.obtener(id);
			ciphertextB64 = cuerpo.ciphertext_b64;
			passwordSaltB64 = cuerpo.password_salt_b64;

			if (cuerpo.password_protected) {
				necesitaPassphrase = true;
				cargando = false;
				return;
			}

			contenido = await descifrarContenidoDeShare(ciphertextB64, claveFragmento, {
				passwordProtected: false
			});
		} catch (err) {
			// Anti-enumeración, igual criterio que el backend: no existe, ya
			// se quemó, expiró o se revocó se muestran todos igual acá — la
			// única distinción real es "clave/passphrase incorrecta" tras un
			// 200 exitoso, que es un problema de descifrado, no del backend.
			error = err instanceof ApiError ? $t.externalShare.noDisponible : $t.externalShare.errorGenerico;
		} finally {
			cargando = false;
		}
	}

	async function desbloquear(e: SubmitEvent) {
		e.preventDefault();
		if (!ciphertextB64 || !claveFragmento) return;
		desbloqueando = true;
		errorPassphrase = undefined;
		try {
			contenido = await descifrarContenidoDeShare(ciphertextB64, claveFragmento, {
				passwordProtected: true,
				passwordSaltB64: passwordSaltB64 ?? undefined,
				passphrase
			});
			necesitaPassphrase = false;
		} catch {
			errorPassphrase = $t.externalShare.errorPassphrase;
		} finally {
			desbloqueando = false;
		}
	}

	onMount(() => {
		cargar();
	});
</script>

<svelte:head>
	<title>{$t.externalShare.titulo} — Ellkan</title>
</svelte:head>

<Card>
	<h1>{$t.externalShare.titulo}</h1>

	{#if cargando}
		<p class="hint">{$t.externalShare.cargando}</p>
	{:else if error}
		<p class="error">{error}</p>
	{:else if necesitaPassphrase}
		<p class="hint">{$t.externalShare.requierePassphrase}</p>
		<form onsubmit={desbloquear}>
			<TextField label={$t.externalShare.passphrase} type="password" bind:value={passphrase} required />
			{#if errorPassphrase}<p class="error">{errorPassphrase}</p>{/if}
			<Button type="submit" variant="primary" loading={desbloqueando}>{$t.externalShare.desbloquear}</Button>
		</form>
	{:else if contenido !== undefined}
		<SecretField label={$t.externalShare.titulo} valor={contenido} />
		<p class="hint">{$t.externalShare.advertenciaUnaVez}</p>
	{/if}
</Card>

<style>
	h1 {
		margin: 0 0 var(--space-4) 0;
		font-size: var(--text-xl);
		color: var(--text-primary);
	}
	.hint {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-3) 0;
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-3) 0;
	}
	form {
		display: flex;
		flex-direction: column;
		gap: var(--space-3);
	}
</style>
