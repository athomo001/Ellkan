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

	// Bug real encontrado (2026-08-11): este form no tenía ningún input para
	// `attribute_mapping` y `guardar()` mandaba `{}` fijo — cada guardado
	// pisaba en silencio el mapeo ya configurado (el repository no hace
	// `coalesce()` en esa columna). Ahora sí se lee/escribe de verdad.
	let mapeoExternalId = $state('');
	let mapeoEmail = $state('');
	let mapeoDisplayName = $state('');

	// Punto 6: filtro base configurable (antes fijo a inetOrgPerson, no
	// servía contra Active Directory) + sync de grupos vía un atributo
	// multivaluado en la propia entrada de usuario (memberOf, estilo AD —
	// funciona igual en OpenLDAP con el overlay memberof activado).
	let userObjectClass = $state('inetOrgPerson');
	let syncGroups = $state(false);
	let groupMembershipAttribute = $state('memberOf');

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
			mapeoExternalId = c.attribute_mapping.external_id ?? '';
			mapeoEmail = c.attribute_mapping.email ?? '';
			mapeoDisplayName = c.attribute_mapping.display_name ?? '';
			userObjectClass = c.user_object_class || 'inetOrgPerson';
			syncGroups = c.sync_groups;
			groupMembershipAttribute = c.group_membership_attribute || 'memberOf';
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
			const attributeMapping: Record<string, string> = {};
			if (mapeoExternalId.trim()) attributeMapping.external_id = mapeoExternalId.trim();
			if (mapeoEmail.trim()) attributeMapping.email = mapeoEmail.trim();
			if (mapeoDisplayName.trim()) attributeMapping.display_name = mapeoDisplayName.trim();

			await directorySyncApi.actualizarConfig({
				ldap_url: ldapUrl || undefined,
				bind_dn: bindDn || undefined,
				bind_password: bindPassword || undefined,
				require_starttls: requireStarttls,
				base_dn: baseDn || undefined,
				user_filter: userFilter || undefined,
				attribute_mapping: attributeMapping,
				user_object_class: userObjectClass.trim() || 'inetOrgPerson',
				sync_groups: syncGroups,
				group_membership_attribute: groupMembershipAttribute.trim() || 'memberOf'
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
			<TextField
				label={$t.admin.directorySync.userObjectClass}
				bind:value={userObjectClass}
				hint={$t.admin.directorySync.userObjectClassHint}
			/>

			<h3>{$t.admin.directorySync.mapeoTitulo}</h3>
			<p class="hint">{$t.admin.directorySync.mapeoHint}</p>
			<TextField label={$t.admin.directorySync.mapeoExternalId} bind:value={mapeoExternalId} placeholder="uid" />
			<TextField label={$t.admin.directorySync.mapeoEmail} bind:value={mapeoEmail} placeholder="mail" />
			<TextField label={$t.admin.directorySync.mapeoDisplayName} bind:value={mapeoDisplayName} placeholder="cn" />

			<h3>{$t.admin.directorySync.gruposTitulo}</h3>
			<label class="check">
				<input type="checkbox" bind:checked={syncGroups} /> {$t.admin.directorySync.syncGroups}
			</label>
			{#if syncGroups}
				<TextField
					label={$t.admin.directorySync.groupMembershipAttribute}
					bind:value={groupMembershipAttribute}
					hint={$t.admin.directorySync.groupMembershipAttributeHint}
				/>
			{/if}

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
			{#if resultado.group_changes.length > 0}
				<p><strong>{$t.admin.directorySync.cambiosGrupos}:</strong></p>
				<ul>
					{#each resultado.group_changes as cambio (cambio.external_id)}
						<li>
							{cambio.external_id}:
							{#if cambio.grupos_nuevos.length}
								<span class="grupos-nuevos">+{cambio.grupos_nuevos.join(', +')}</span>
							{/if}
							{#if cambio.grupos_removidos.length}
								<span class="grupos-removidos">−{cambio.grupos_removidos.join(', −')}</span>
							{/if}
						</li>
					{/each}
				</ul>
			{/if}
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
	.resultado ul {
		margin: 0 0 var(--space-2) 0;
		padding-left: var(--space-4);
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.grupos-nuevos {
		color: var(--success);
		margin-right: var(--space-2);
	}
	.grupos-removidos {
		color: var(--danger);
	}
	h3 {
		margin: var(--space-4) 0 var(--space-1) 0;
		font-size: var(--text-sm);
		font-weight: 600;
		color: var(--text-primary);
	}
	:global(.card) + :global(.card) {
		margin-top: var(--space-4);
	}
</style>
