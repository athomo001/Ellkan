<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-01: "Inspector de claves" — sección de "Mi cuenta". Sólo lectura,
	// nunca expone ni permite exportar la clave privada.
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import { perfilApi, type Perfil } from '$lib/api/profile';
	import { bytesABase64 } from '$lib/crypto/b64';
	import { clavesDesbloqueadas } from '$lib/state/session';
	import { t } from '$lib/i18n';

	let perfil = $state<Perfil | undefined>();
	onMount(() => {
		perfilApi.obtener().then((p) => (perfil = p)).catch(() => {});
	});

	let fingerprintX25519 = $state<string | undefined>();
	let fingerprintEd25519 = $state<string | undefined>();
	$effect(() => {
		const claves = $clavesDesbloqueadas;
		if (!claves) {
			fingerprintX25519 = undefined;
			fingerprintEd25519 = undefined;
			return;
		}
		(async () => {
			fingerprintX25519 = bytesABase64(
				new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(claves.x25519Public)))
			).slice(0, 16);
			fingerprintEd25519 = bytesABase64(
				new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(claves.ed25519Public)))
			).slice(0, 16);
		})();
	});
</script>

<svelte:head>
	<title>{$t.settingsProfile.clavesTitulo} — Ellkan</title>
</svelte:head>

<h1>{$t.settingsProfile.clavesTitulo}</h1>
<Card>
	<p class="hint">{$t.settingsProfile.clavesHint}</p>
	{#if fingerprintX25519 && fingerprintEd25519}
		<dl>
			<dt>{$t.settingsProfile.clavesFingerprintX25519}</dt>
			<dd class="mono">{fingerprintX25519}</dd>
			<dt>{$t.settingsProfile.clavesFingerprintEd25519}</dt>
			<dd class="mono">{fingerprintEd25519}</dd>
			{#if perfil}
				<dt>{$t.settingsProfile.clavesCreadas}</dt>
				<dd>{new Date(perfil.keys_created_at).toLocaleString()}</dd>
			{/if}
		</dl>
	{:else}
		<p class="hint">{$t.settingsProfile.clavesBloqueadas}</p>
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
	dl {
		display: grid;
		grid-template-columns: auto 1fr;
		gap: var(--space-1) var(--space-4);
		margin: 0;
	}
	dt {
		color: var(--text-secondary);
		font-size: var(--text-sm);
	}
	dd {
		margin: 0;
		color: var(--text-primary);
		font-size: var(--text-sm);
	}
	dd.mono {
		font-family: var(--font-mono);
	}
</style>
