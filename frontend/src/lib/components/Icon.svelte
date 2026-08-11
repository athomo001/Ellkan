<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// Wrapper reusable para los íconos de línea (Heroicons outline, 24x24,
	// stroke-width 1.5) que ya usa la nav (`(app)/+layout.svelte::ICONOS`) —
	// antes cada lugar repetía el mismo `<svg>` a mano; esto evita duplicar
	// el boilerplate en cada botón nuevo que necesite un ícono.
	let { path, size = 16 }: { path: string | string[]; size?: number } = $props();
	const paths = $derived(Array.isArray(path) ? path : [path]);
</script>

<svg
	xmlns="http://www.w3.org/2000/svg"
	fill="none"
	viewBox="0 0 24 24"
	stroke-width="1.5"
	stroke="currentColor"
	width={size}
	height={size}
	aria-hidden="true"
>
	{#each paths as d (d)}
		<path stroke-linecap="round" stroke-linejoin="round" {d} />
	{/each}
</svg>
