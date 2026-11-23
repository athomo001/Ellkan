<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// QA-09 (rotación): si la organización generó una clave de recuperación
	// nueva y el escrow propio sigue sellado contra la anterior, se avisa al
	// entrar y se re-sella sólo con la confirmación del usuario (mostrando la
	// huella de la clave nueva, F-16: nunca un re-sellado silencioso contra
	// una clave que entrega el servidor).
	import { onMount } from 'svelte';
	import { get } from 'svelte/store';
	import Button from './Button.svelte';
	import { accountRecoveryApi, type ClaveOrg } from '$lib/api/accountRecovery';
	import { enrolarConClaveVigente } from '$lib/crypto/accountRecovery';
	import { huellaDeClave } from '$lib/crypto/emergencia';
	import { clavesDesbloqueadas } from '$lib/state/session';
	import { ApiError } from '$lib/api/client';
	import { t } from '$lib/i18n';

	// Una sola consulta por carga de la app; "Ahora no" la oculta hasta el
	// próximo login.
	let clave = $state<ClaveOrg | undefined>();
	let huella = $state('');
	let actualizando = $state(false);
	let listo = $state(false);
	let error = $state<string | undefined>();

	onMount(async () => {
		try {
			const estado = await accountRecoveryApi.miEstado();
			if (!estado.enrolled || estado.current_org_recovery_key_id === null) return;
			if (estado.org_recovery_key_id === estado.current_org_recovery_key_id) return;
			const vigente = await accountRecoveryApi.orgPublicKey();
			huella = await huellaDeClave(vigente.public_key_x25519_b64);
			clave = vigente;
		} catch {
			/* sin servidor (escritorio sin vincular) o sin F-16: no hay nada que avisar */
		}
	});

	async function actualizar() {
		error = undefined;
		const claves = get(clavesDesbloqueadas);
		if (!claves || !clave) {
			error = get(t).settingsSecurity.recoveryClavesBloqueadas;
			return;
		}
		actualizando = true;
		try {
			await enrolarConClaveVigente(claves, clave);
			listo = true;
			clave = undefined;
		} catch (err) {
			error = err instanceof ApiError ? err.message : get(t).settingsSecurity.recoveryErrorHabilitar;
		} finally {
			actualizando = false;
		}
	}
</script>

{#if clave}
	<div class="aviso" role="status">
		<strong>{$t.settingsSecurity.recoveryDesactualizadaTitulo}</strong>
		<p>{$t.settingsSecurity.recoveryDesactualizada}</p>
		<p class="huella">{$t.settingsSecurity.recoveryHuella.replace('{huella}', huella)}</p>
		{#if error}<p class="error">{error}</p>{/if}
		<div class="acciones">
			<Button variant="primary" onclick={actualizar} loading={actualizando}>{$t.settingsSecurity.recoveryActualizar}</Button>
			<Button variant="ghost" onclick={() => (clave = undefined)}>{$t.settingsSecurity.recoveryAhoraNo}</Button>
		</div>
	</div>
{:else if listo}
	<div class="aviso" role="status"><p class="ok">{$t.settingsSecurity.recoveryActualizada}</p></div>
{/if}

<style>
	.aviso {
		margin-bottom: var(--space-4);
		padding: var(--space-3) var(--space-4);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		background: var(--bg-overlay);
		color: var(--text-primary);
	}
	p {
		margin: var(--space-2) 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.huella {
		font-family: var(--font-mono, monospace);
	}
	.acciones {
		display: flex;
		gap: var(--space-2);
	}
	.error {
		color: var(--danger);
	}
	.ok {
		color: var(--success);
	}
</style>
