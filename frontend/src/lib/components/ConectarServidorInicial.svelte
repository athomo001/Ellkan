<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-47, primer arranque de la app de escritorio: en vez de crear una cuenta
	// local nueva, se usa la que ya existe en un servidor Ellkan. La bóveda
	// local nace con la identidad del servidor (ver
	// `sync/vinculacion.ts::conectarDesdeServidor`), queda vinculada, se elige
	// el modo de persistencia y se trae todo con un primer sync.
	import { goto } from '$app/navigation';
	import { get } from 'svelte/store';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';
	import { iniciarSesion } from '$lib/crypto/identity';
	import { sesion, clavesDesbloqueadas } from '$lib/state/session';
	import { recoveryKitApi } from '$lib/api/recoveryKit';
	import { conectarDesdeServidor } from '$lib/sync/vinculacion';
	import { cambiarPersistencia, type ModoPersistencia } from '$lib/sync/persistencia';
	import { sincronizarAhora } from '$lib/sync/motor';

	let servidor = $state('');
	let email = $state('');
	let passphrase = $state('');
	let modo = $state<ModoPersistencia>('full');
	let cargando = $state(false);
	let paso = $state<string | undefined>();
	let error = $state<string | undefined>();

	const MODOS: ModoPersistencia[] = ['full', 'memory', 'names_only'];

	async function conectar(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;
		cargando = true;
		const textos = get(t).conectarInicial;
		try {
			paso = textos.pasoServidor;
			await conectarDesdeServidor(servidor, email, passphrase);

			// La bóveda local ya existe con la misma passphrase: login local normal.
			paso = textos.pasoLocal;
			const login = await iniciarSesion(email, passphrase);
			if (login.estado !== 'completo' || !login.claves) throw new Error(textos.errorLoginLocal);
			sesion.set({ sessionId: login.sessionId ?? null, userId: login.userId ?? null, email });
			clavesDesbloqueadas.set(login.claves);

			await cambiarPersistencia(modo);

			// Primer sync: si falla (red), la cuenta ya quedó vinculada y se
			// reintenta solo; no tiene sentido frenar la entrada por eso.
			paso = textos.pasoSync;
			try {
				await sincronizarAhora();
			} catch {
				/* se reintenta en el próximo sync automático */
			}

			const kit = await recoveryKitApi.estado().catch(() => undefined);
			goto(kit && !kit.configured ? '/onboarding/recovery-kit' : '/vault');
		} catch (err) {
			error = err instanceof ApiError || err instanceof Error ? err.message : textos.errorGenerico;
		} finally {
			cargando = false;
			paso = undefined;
		}
	}
</script>

<form onsubmit={conectar}>
	<TextField
		label={$t.conectarInicial.servidor}
		bind:value={servidor}
		placeholder="https://ellkan.miempresa.com"
		hint={$t.conectarInicial.servidorHint}
		required
	/>
	<TextField label={$t.registro.email} type="email" bind:value={email} autocomplete="email" required />
	<TextField label={$t.conectarInicial.passphrase} type="password" bind:value={passphrase} autocomplete="current-password" required />

	<fieldset>
		<legend>{$t.conectarInicial.modo}</legend>
		{#each MODOS as m (m)}
			<label class="modo">
				<input type="radio" name="modo" value={m} bind:group={modo} />
				<span>
					<strong>{$t.conectarInicial.modos[m].titulo}</strong>
					<small>{$t.conectarInicial.modos[m].detalle}</small>
				</span>
			</label>
		{/each}
	</fieldset>

	{#if error}<p class="error">{error}</p>{/if}
	{#if paso}<p class="paso">{paso}</p>{/if}
	<Button type="submit" variant="primary" loading={cargando}>{$t.conectarInicial.conectar}</Button>
</form>

<style>
	form {
		display: flex;
		flex-direction: column;
	}
	fieldset {
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-3);
		margin: 0 0 var(--space-4) 0;
	}
	legend {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		padding: 0 var(--space-1);
	}
	.modo {
		display: flex;
		gap: var(--space-2);
		align-items: flex-start;
		padding: var(--space-2) 0;
		cursor: pointer;
	}
	.modo span {
		display: flex;
		flex-direction: column;
		gap: 2px;
	}
	.modo strong {
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.modo small {
		font-size: var(--text-xs);
		color: var(--text-secondary);
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-4) 0;
	}
	.paso {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-4) 0;
	}
</style>
