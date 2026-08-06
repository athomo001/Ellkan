<!-- Autor: Athan Espinoza -->
<script lang="ts">
	import type { Snippet } from 'svelte';
	let { children, padded = true }: { children: Snippet; padded?: boolean } = $props();
</script>

<div class="card" class:padded>
	{@render children()}
</div>

<style>
	.card {
		background: var(--bg-raised);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-md);
	}
	.padded {
		padding: var(--space-6);
	}
</style>
