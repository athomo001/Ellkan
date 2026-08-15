<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// Sin guard de sesión propio todavía (llega con /vault, F-07) — por ahora
	// la raíz sólo redirige a la primera pantalla real que existe.
	import { goto } from '$app/navigation';
	import { onMount } from 'svelte';

	onMount(() => {
		goto('/login', { replaceState: true });
	});
</script>
