<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// Pendiente #57: links a la política de privacidad y a los términos de la
	// instancia, si el admin los cargó (`GET /auth/setup-status`). Sin links,
	// no muestra nada. El servidor sólo acepta http(s).
	import { onMount } from 'svelte';
	import { api } from '#lib/api/client';
	import { t } from '#lib/i18n';

	let privacidad = $state<string | null>(null);
	let terminos = $state<string | null>(null);

	onMount(() => {
		api
			.get<{ privacy_url?: string | null; terms_url?: string | null }>('/auth/setup-status')
			.then((s) => {
				privacidad = s.privacy_url ?? null;
				terminos = s.terms_url ?? null;
			})
			.catch(() => {});
	});
</script>

{#if privacidad || terminos}
	<p class="legales">
		{#if privacidad}<a href={privacidad} target="_blank" rel="noreferrer">{$t.legales.privacidad}</a>{/if}
		{#if privacidad && terminos}<span aria-hidden="true">·</span>{/if}
		{#if terminos}<a href={terminos} target="_blank" rel="noreferrer">{$t.legales.terminos}</a>{/if}
	</p>
{/if}

<style>
	.legales {
		display: flex;
		justify-content: center;
		gap: var(--space-2);
		margin: var(--space-3) 0 0 0;
		font-size: var(--text-xs, 0.75rem);
		color: var(--text-secondary);
	}
	a {
		color: var(--text-secondary);
	}
</style>
