<!-- Autor: Athan Espinoza -->
<script lang="ts">
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import { directorySyncApi, type ResultadoSync } from '$lib/api/admin';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let cargando = $state(true);
	let guardando = $state(false);
	let error = $state<string | undefined>();
	let guardado = $state(false);

	let ldapUrl = $state('');
	let bindDn = $state('');
	let bindPassword = $state('');
	let requireStarttls = $state(true);
	let baseDn = $state('');
	let userFilter = $state('');
	let ultimaSync = $state<string | null>(null);

	onMount(cargar);

	async function cargar() {
		cargando = true;
		try {
			const c = await directorySyncApi.obtenerConfig();
			ldapUrl = c.ldap_url ?? '';
			bindDn = c.bind_dn ?? '';
			requireStarttls = c.require_starttls;
			baseDn = c.base_dn ?? '';
			userFilter = c.user_filter ?? '';
			ultimaSync = c.last_sync_at;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			cargando = false;
		}
	}

	async function guardar(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;
		guardado = false;
		guardando = true;
		try {
			await directorySyncApi.actualizarConfig({
				ldap_url: ldapUrl || undefined,
				bind_dn: bindDn || undefined,
				bind_password: bindPassword || undefined,
				require_starttls: requireStarttls,
				base_dn: baseDn || undefined,
				user_filter: userFilter || undefined,
				attribute_mapping: {}
			});
			bindPassword = '';
			guardado = true;
			await cargar();
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			guardando = false;
		}
	}

	let corriendo = $state(false);
	let resultado = $state<ResultadoSync | undefined>();
	let errorSync = $state<string | undefined>();

	async function correr(fn: () => Promise<ResultadoSync>) {
		errorSync = undefined;
		corriendo = true;
		resultado = undefined;
		try {
			resultado = await fn();
		} catch (err) {
			errorSync = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			corriendo = false;
		}
	}
</script>

<h1>{$t.admin.directorySync.titulo}</h1>
<Card>
	{#if cargando}
		<p>{$t.admin.comun.cargando}</p>
	{:else}
		<form onsubmit={guardar}>
			<TextField label={$t.admin.directorySync.ldapUrl} bind:value={ldapUrl} />
			<TextField label={$t.admin.directorySync.bindDn} bind:value={bindDn} />
			<TextField label={$t.admin.directorySync.bindPassword} type="password" bind:value={bindPassword} />
			<label class="check">
				<input type="checkbox" bind:checked={requireStarttls} /> {$t.admin.directorySync.requireStarttls}
			</label>
			<TextField label={$t.admin.directorySync.baseDn} bind:value={baseDn} />
			<TextField label={$t.admin.directorySync.userFilter} bind:value={userFilter} />
			<p class="hint">
				{$t.admin.directorySync.ultimaSync}: {ultimaSync ?? $t.admin.directorySync.nunca}
			</p>
			{#if error}<p class="error">{error}</p>{/if}
			{#if guardado}<p class="ok">{$t.admin.comun.guardado}</p>{/if}
			<Button type="submit" variant="primary" loading={guardando}>{$t.admin.comun.guardar}</Button>
		</form>
	{/if}
</Card>

<Card>
	<div class="botones">
		<Button variant="secondary" onclick={() => correr(directorySyncApi.dryRun)} loading={corriendo}
			>{$t.admin.directorySync.dryRun}</Button
		>
		<Button variant="primary" onclick={() => correr(directorySyncApi.aplicar)} loading={corriendo}
			>{$t.admin.directorySync.aplicar}</Button
		>
	</div>
	{#if errorSync}<p class="error">{errorSync}</p>{/if}
	{#if resultado}
		<div class="resultado">
			<p><strong>{$t.admin.directorySync.crear}:</strong> {resultado.would_create.join(', ') || '—'}</p>
			<p><strong>{$t.admin.directorySync.reactivar}:</strong> {resultado.would_reactivate.join(', ') || '—'}</p>
			<p><strong>{$t.admin.directorySync.desactivar}:</strong> {resultado.would_deactivate.join(', ') || '—'}</p>
			<p><strong>{$t.admin.directorySync.sinCambios}:</strong> {resultado.unchanged}</p>
			<p><strong>{$t.admin.directorySync.conflictos}:</strong> {resultado.conflicts.join(', ') || '—'}</p>
		</div>
	{/if}
</Card>

<style>
	h1 {
		margin: 0 0 var(--space-6) 0;
		font-size: var(--text-2xl);
		color: var(--text-primary);
	}
	form {
		display: flex;
		flex-direction: column;
		max-width: 28rem;
	}
	.check {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		margin-bottom: var(--space-4);
	}
	.hint {
		color: var(--text-muted);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-4) 0;
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
	}
	.ok {
		color: var(--success);
		font-size: var(--text-sm);
	}
	.botones {
		display: flex;
		gap: var(--space-2);
		margin-bottom: var(--space-4);
	}
	.resultado p {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0 0 var(--space-2) 0;
	}
	:global(.card) + :global(.card) {
		margin-top: var(--space-4);
	}
</style>
