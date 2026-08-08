<script lang="ts">
	import '$lib/styles/base.css';
	import { preferencias } from '$lib/state/session';
	import { aplicarTema } from '$lib/api/preferences';

	let { children } = $props();

	// Aplica el tema guardado (persiste en disco, sobrevive logout — F-30)
	// desde antes de cualquier login: la pantalla de login también debe
	// respetar la preferencia elegida en una sesión anterior.
	$effect(() => {
		aplicarTema($preferencias.theme);
	});
</script>

{@render children()}
