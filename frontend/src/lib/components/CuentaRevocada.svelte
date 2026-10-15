<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// Revocación remota (docs/revocacion-remota.md): pantalla fija, encima de
	// todo, cuando el servidor vinculado revocó la cuenta y la bóveda local ya
	// se borró. No hay forma de volver a la app desde acá: sólo cerrarla. Al
	// abrirla de nuevo arranca como recién instalada.
	import Button from '$lib/components/Button.svelte';
	import { t } from '$lib/i18n';
	import { cerrarAplicacion } from '$lib/tauri/ventana';
	import { atraparFoco } from '$lib/a11y/foco';

	let { servidor, motivo }: { servidor: string; motivo: 'deactivated' | 'purged' } = $props();
</script>

<div class="fondo" role="alertdialog" aria-modal="true" aria-labelledby="revocada-titulo">
	<div class="panel" use:atraparFoco>
		<h1 id="revocada-titulo">{$t.revocacion.titulo}</h1>
		<p>{motivo === 'purged' ? $t.revocacion.textoPurgada(servidor) : $t.revocacion.textoBloqueada(servidor)}</p>
		<p class="hint">{$t.revocacion.borrado}</p>
		<Button variant="primary" onclick={() => cerrarAplicacion()}>{$t.revocacion.cerrar}</Button>
	</div>
</div>

<style>
	.fondo {
		position: fixed;
		inset: 0;
		z-index: 10000;
		display: flex;
		align-items: center;
		justify-content: center;
		padding: var(--space-6);
		background: var(--bg-base);
	}
	.panel {
		max-width: 32rem;
		display: flex;
		flex-direction: column;
		gap: var(--space-4);
		padding: var(--space-6);
		border: 1px solid var(--danger);
		border-radius: var(--radius-md, 8px);
		background: var(--bg-raised);
	}
	h1 {
		margin: 0;
		font-size: var(--text-xl);
		color: var(--danger);
	}
	p {
		margin: 0;
		color: var(--text-primary);
	}
	.hint {
		color: var(--text-secondary);
		font-size: var(--text-sm);
	}
</style>
