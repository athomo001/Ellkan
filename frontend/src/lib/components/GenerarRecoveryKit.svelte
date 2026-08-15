<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// Recovery kit: genera un par X25519 nuevo en el cliente, muestra la
	// privada UNA sola vez, y sólo habilita "ya lo guardé"/finalizar después
	// de que el usuario descargó o copió el valor — nunca antes. Usado tanto
	// en onboarding (obligatorio, `mensaje` variante según el motivo) como
	// en Ajustes (regeneración voluntaria) — mismo componente, nunca
	// re-muestra un kit ya generado antes.
	import { get } from 'svelte/store';
	import Button from '$lib/components/Button.svelte';
	import { generarClaveEfimera, sellarMaterialParaKit } from '$lib/crypto/accountRecovery';
	import { recoveryKitApi } from '$lib/api/recoveryKit';
	import { clavesDesbloqueadas } from '$lib/state/session';
	import { bytesABase64 } from '$lib/crypto/b64';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let { mensaje, onGenerado }: { mensaje: string; onGenerado: () => void } = $props();

	let generando = $state(true);
	let error = $state<string | undefined>();
	let kitPrivadaB64 = $state<string | undefined>();
	let kitPublicaB64 = $state<string | undefined>();
	let selladoB64 = $state<string | undefined>();
	let yaGuardado = $state(false);
	let confirmado = $state(false);
	let finalizando = $state(false);
	let copiado = $state(false);

	async function generar() {
		generando = true;
		error = undefined;
		const claves = get(clavesDesbloqueadas);
		if (!claves) {
			error = $t.recoveryKit.errorClavesBloqueadas;
			generando = false;
			return;
		}
		try {
			const kit = await generarClaveEfimera();
			kitPrivadaB64 = bytesABase64(kit.privada);
			kitPublicaB64 = kit.publicaB64;
			selladoB64 = await sellarMaterialParaKit(kit.publicaB64, claves);
		} catch (err) {
			error = err instanceof ApiError || err instanceof Error ? err.message : $t.recoveryKit.errorGenerico;
		} finally {
			generando = false;
		}
	}
	generar();

	function descargar() {
		if (!kitPrivadaB64) return;
		const blob = new Blob([kitPrivadaB64], { type: 'text/plain' });
		const url = URL.createObjectURL(blob);
		const a = document.createElement('a');
		a.href = url;
		a.download = 'ellkan-recovery-kit.txt';
		a.click();
		URL.revokeObjectURL(url);
		yaGuardado = true;
	}

	async function copiar() {
		if (!kitPrivadaB64) return;
		try {
			await navigator.clipboard.writeText(kitPrivadaB64);
			copiado = true;
			yaGuardado = true;
		} catch {
			/* clipboard puede fallar por permisos del navegador — descargar sigue disponible */
		}
	}

	async function finalizar() {
		if (!kitPublicaB64 || !selladoB64) return;
		finalizando = true;
		error = undefined;
		try {
			await recoveryKitApi.generar(kitPublicaB64, selladoB64);
			onGenerado();
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.recoveryKit.errorGenerico;
		} finally {
			finalizando = false;
		}
	}
</script>

<p class="mensaje">{mensaje}</p>

{#if generando}
	<p class="hint">{$t.recoveryKit.generando}</p>
{:else if error && !kitPrivadaB64}
	<p class="error">{error}</p>
	<Button variant="secondary" onclick={generar}>{$t.recoveryKit.reintentar}</Button>
{:else if kitPrivadaB64}
	<p class="advertencia">{$t.recoveryKit.advertencia}</p>
	<code class="kit">{kitPrivadaB64}</code>
	<div class="acciones-kit">
		<Button variant="secondary" onclick={descargar}>{$t.recoveryKit.descargar}</Button>
		<Button variant="secondary" onclick={copiar}>{copiado ? $t.recoveryKit.copiado : $t.recoveryKit.copiar}</Button>
	</div>
	<label class="check">
		<input type="checkbox" bind:checked={confirmado} disabled={!yaGuardado} />
		{$t.recoveryKit.confirmacion}
	</label>
	{#if error}<p class="error">{error}</p>{/if}
	<Button variant="primary" onclick={finalizar} disabled={!confirmado} loading={finalizando}>
		{$t.recoveryKit.finalizar}
	</Button>
{/if}

<style>
	.mensaje {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-4) 0;
	}
	.hint {
		color: var(--text-secondary);
		font-size: var(--text-sm);
	}
	.advertencia {
		color: var(--danger);
		font-size: var(--text-sm);
		font-weight: 600;
		margin: 0 0 var(--space-3) 0;
	}
	.kit {
		display: block;
		font-family: var(--font-mono);
		font-size: var(--text-sm);
		word-break: break-all;
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-3);
		margin-bottom: var(--space-4);
	}
	.acciones-kit {
		display: flex;
		gap: var(--space-2);
		margin-bottom: var(--space-4);
	}
	.check {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-sm);
		color: var(--text-primary);
		margin-bottom: var(--space-4);
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-4) 0;
	}
</style>
