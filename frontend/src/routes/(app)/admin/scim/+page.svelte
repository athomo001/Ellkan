<!-- Autor: Athan Espinoza -->
<script lang="ts">
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import { scimApi } from '$lib/api/admin';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let generando = $state(false);
	let error = $state<string | undefined>();
	let token = $state<string | undefined>();

	async function generar() {
		error = undefined;
		generando = true;
		try {
			token = (await scimApi.crearToken()).token;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			generando = false;
		}
	}
</script>

<h1>{$t.admin.scim.titulo}</h1>
<Card>
	<p class="hint">{$t.admin.scim.hint}</p>
	{#if error}<p class="error">{error}</p>{/if}
	{#if token}
		<p class="ok">{$t.admin.scim.tokenGenerado}</p>
		<code class="token">{token}</code>
	{/if}
	<Button variant="primary" onclick={generar} loading={generando}>{$t.admin.scim.generar}</Button>
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
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
	}
	.ok {
		color: var(--success);
		font-size: var(--text-sm);
		margin-bottom: var(--space-2);
	}
	.token {
		display: block;
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-3);
		margin-bottom: var(--space-4);
		font-family: var(--font-mono);
		word-break: break-all;
		color: var(--text-primary);
	}
</style>
