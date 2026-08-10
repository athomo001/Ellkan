<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-01: "Token de seguridad" — sección de "Mi cuenta", 100% client-side
	// (ver $lib/state/securityToken.ts para el porqué).
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import { obtenerTokenSeguridad, generarTokenSeguridad, COLOR_HEX, type TokenSeguridad } from '$lib/state/securityToken';
	import { sesion } from '$lib/state/session';
	import { t } from '$lib/i18n';

	const email = $derived($sesion.email ?? '');
	let token = $state<TokenSeguridad | null>(null);

	onMount(() => {
		if (email) token = obtenerTokenSeguridad(email);
	});

	function aleatorizar() {
		if (!email) return;
		token = generarTokenSeguridad(email);
	}
</script>

<svelte:head>
	<title>{$t.settingsProfile.tokenTitulo} — Ellkan</title>
</svelte:head>

<h1>{$t.settingsProfile.tokenTitulo}</h1>
<Card>
	<p class="hint">{$t.settingsProfile.tokenHint}</p>
	{#if token}
		<p class="token">
			<span class="punto-token" style:background={COLOR_HEX[token.color]}></span>
			<strong>{token.palabra}</strong>
		</p>
	{:else}
		<p class="hint">{$t.settingsProfile.tokenSinToken}</p>
	{/if}
	<Button variant="secondary" onclick={aleatorizar}>{$t.settingsProfile.tokenAleatorizar}</Button>
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
	.token {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-base);
		color: var(--text-primary);
		margin: 0 0 var(--space-4) 0;
	}
	.punto-token {
		display: inline-block;
		width: 1rem;
		height: 1rem;
		border-radius: 50%;
		border: 1px solid var(--border-color);
	}
</style>
