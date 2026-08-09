<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-26: gestión de los links externos que este usuario creó — crear se
	// hace desde el Vault (necesita el contenido descifrado de un recurso
	// puntual, `(app)/vault/+page.svelte::crearExterno`); acá sólo se listan
	// y se revocan, server-side sólo guarda metadata (nunca `ciphertext` en
	// este listado).
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import Table from '$lib/components/Table.svelte';
	import { externalSharesApi, type ExternalShareResumen } from '$lib/api/externalShares';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let cargando = $state(true);
	let error = $state<string | undefined>();
	let shares = $state<ExternalShareResumen[]>([]);
	let revocandoId = $state<string | undefined>();

	async function cargar() {
		cargando = true;
		error = undefined;
		try {
			shares = await externalSharesApi.listar();
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			cargando = false;
		}
	}

	function estado(s: ExternalShareResumen): string {
		if (s.revoked_at) return $t.settingsExternalShares.revocado;
		if (s.burned_at) return $t.settingsExternalShares.consumido;
		if (new Date(s.expires_at).getTime() <= Date.now()) return $t.settingsExternalShares.expirado;
		return $t.settingsExternalShares.activo;
	}

	async function revocar(s: ExternalShareResumen) {
		revocandoId = s.id;
		try {
			await externalSharesApi.revocar(s.id);
			await cargar();
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			revocandoId = undefined;
		}
	}

	onMount(cargar);
</script>

<svelte:head>
	<title>{$t.settingsExternalShares.titulo} — Ellkan</title>
</svelte:head>

<h1>{$t.settingsExternalShares.titulo}</h1>

<Card>
	{#if error}<p class="error">{error}</p>{/if}
	<Table
		columnas={[
			{ key: 'estado', header: $t.settingsExternalShares.estado },
			{ key: 'protegido', header: $t.settingsExternalShares.protegido },
			{ key: 'vistas', header: $t.settingsExternalShares.vistas },
			{ key: 'expira', header: $t.settingsExternalShares.expira },
			{ key: 'creado', header: $t.settingsExternalShares.creado },
			{ key: 'acciones', header: '' }
		]}
		filas={shares}
		claveFila={(s) => s.id}
		{cargando}
		textoCargando={$t.admin.comun.cargando}
		vacio={$t.settingsExternalShares.sinShares}
	>
		{#snippet fila(s: ExternalShareResumen)}
			<td>{estado(s)}</td>
			<td>{s.password_protected ? $t.admin.comun.si : $t.admin.comun.no}</td>
			<td>{s.view_count} / {s.max_views}</td>
			<td>{new Date(s.expires_at).toLocaleString()}</td>
			<td>{new Date(s.created_at).toLocaleString()}</td>
			<td>
				{#if !s.revoked_at && !s.burned_at}
					<Button variant="ghost" onclick={() => revocar(s)} loading={revocandoId === s.id}>
						{$t.settingsExternalShares.revocar}
					</Button>
				{/if}
			</td>
		{/snippet}
	</Table>
</Card>

<style>
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-4) 0;
	}
</style>
