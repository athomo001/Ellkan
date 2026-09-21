<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// Se muestra cuando el usuario cierra la ventana (la "X" o Alt+F4) y la
	// preferencia es "preguntar". Existe porque cerrar a la bandeja SIN avisar
	// confundía: el usuario creía haber cerrado la app y seguía corriendo.
	import Modal from '$lib/components/Modal.svelte';
	import Button from '$lib/components/Button.svelte';
	import { t } from '$lib/i18n';
	import { configurarAlCerrar, cerrarAplicacion, ocultarABandeja } from '$lib/tauri/ventana';

	let { onCerrar }: { onCerrar: () => void } = $props();

	let recordar = $state(false);
	let error = $state<string | undefined>();
	let trabajando = $state(false);

	async function elegir(modo: 'bandeja' | 'salir') {
		error = undefined;
		trabajando = true;
		try {
			// Guardar la elección ANTES de cerrar: si la app termina primero, no
			// llega a persistirse.
			if (recordar) await configurarAlCerrar(modo);
			if (modo === 'salir') {
				await cerrarAplicacion();
			} else {
				await ocultarABandeja();
				onCerrar();
			}
		} catch (err) {
			error = typeof err === 'string' ? err : $t.cierre.errorGenerico;
		} finally {
			trabajando = false;
		}
	}
</script>

<Modal titulo={$t.cierre.titulo} {onCerrar}>
	<p class="texto">{$t.cierre.texto}</p>

	<div class="acciones">
		<Button variant="primary" onclick={() => elegir('salir')} disabled={trabajando}>{$t.cierre.cerrarTodo}</Button>
		<Button onclick={() => elegir('bandeja')} disabled={trabajando}>{$t.cierre.bandeja}</Button>
		<Button onclick={onCerrar} disabled={trabajando}>{$t.cierre.cancelar}</Button>
	</div>

	<label class="recordar">
		<input type="checkbox" bind:checked={recordar} />
		{$t.cierre.recordar}
	</label>
	<p class="hint">{$t.cierre.hintCambiar}</p>

	{#if error}<p class="error">{error}</p>{/if}
</Modal>

<style>
	.texto {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-4) 0;
	}
	.acciones {
		display: flex;
		flex-wrap: wrap;
		gap: var(--space-2);
		margin-bottom: var(--space-4);
	}
	.recordar {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.hint {
		color: var(--text-secondary);
		font-size: var(--text-xs);
		margin: var(--space-2) 0 0 0;
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
		margin: var(--space-2) 0 0 0;
	}
</style>
