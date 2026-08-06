<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// Layout minimalista (07-frontend-web.md §3): sin nav lateral, sin
	// bundle del panel de administración — es la primera carga que ve
	// cualquiera antes de autenticarse.
	import type { Snippet } from 'svelte';
	let { children }: { children: Snippet } = $props();
</script>

<div class="anon-shell">
	<main>
		{@render children()}
	</main>
</div>

<style>
	.anon-shell {
		min-height: 100vh;
		display: flex;
		align-items: center;
		justify-content: center;
		background: var(--bg-base);
		padding: var(--space-6);
	}
	main {
		width: 100%;
		max-width: 24rem;
	}
</style>
