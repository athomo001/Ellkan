<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// Link al código fuente que exige la AGPL-3.0 §13: quien use Ellkan por
	// red tiene que poder obtener el código de la versión que corre. Un
	// operador que modifique Ellkan y lo ofrezca a otros debe apuntar a SU
	// código, no al repo oficial: lo define al compilar el frontend con
	// `VITE_ELLKAN_SOURCE_URL`. Sin esa variable, apunta al repo oficial.
	import { t } from '$lib/i18n';

	let { compacto = false }: { compacto?: boolean } = $props();

	const URL_CODIGO_FUENTE: string = import.meta.env.VITE_ELLKAN_SOURCE_URL || 'https://github.com/athomo001/Ellkan';
</script>

<a class="codigo-fuente" class:compacto href={URL_CODIGO_FUENTE} target="_blank" rel="noreferrer" title={$t.appShell.codigoFuenteTitulo} aria-label={$t.appShell.codigoFuenteTitulo}>
	{compacto ? '</>' : $t.appShell.codigoFuente}
</a>

<style>
	.codigo-fuente {
		align-self: center;
		font-size: var(--text-xs, 0.75rem);
		color: var(--text-secondary);
		text-decoration: underline;
		text-underline-offset: 2px;
	}
	.codigo-fuente:hover,
	.codigo-fuente:focus-visible {
		color: var(--text-primary);
	}
	.compacto {
		text-decoration: none;
	}
</style>
