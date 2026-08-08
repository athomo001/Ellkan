<!-- Autor: Athan Espinoza -->
<script lang="ts">
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import Table from '$lib/components/Table.svelte';
	import { rolesApi, type Rol } from '$lib/api/admin';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let cargando = $state(true);
	let error = $state<string | undefined>();
	let roles = $state<Rol[]>([]);

	async function cargar() {
		cargando = true;
		error = undefined;
		try {
			roles = await rolesApi.listar();
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			cargando = false;
		}
	}
	onMount(cargar);

	let mostrarNuevo = $state(false);
	let nombreNuevo = $state('');
	let permisosNuevo = $state('');
	let creando = $state(false);

	async function crear(e: SubmitEvent) {
		e.preventDefault();
		creando = true;
		error = undefined;
		try {
			await rolesApi.crear(
				nombreNuevo,
				permisosNuevo.split('\n').map((s) => s.trim()).filter(Boolean)
			);
			nombreNuevo = '';
			permisosNuevo = '';
			mostrarNuevo = false;
			await cargar();
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			creando = false;
		}
	}

	let editandoId = $state<string | undefined>();
	let permisosEditar = $state('');
	let guardandoEdicion = $state(false);

	function empezarEdicion(rol: Rol) {
		editandoId = rol.id;
		permisosEditar = rol.permissions.join('\n');
	}

	async function guardarEdicion(e: SubmitEvent) {
		e.preventDefault();
		if (!editandoId) return;
		guardandoEdicion = true;
		error = undefined;
		try {
			await rolesApi.actualizarPermisos(
				editandoId,
				permisosEditar.split('\n').map((s) => s.trim()).filter(Boolean)
			);
			editandoId = undefined;
			await cargar();
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			guardandoEdicion = false;
		}
	}
</script>

<h1>{$t.admin.roles.titulo}</h1>
<Card>
	{#if cargando}
		<p>{$t.admin.comun.cargando}</p>
	{:else}
		{#if error}<p class="error">{error}</p>{/if}

		<div class="cabecera">
			<Button variant="primary" onclick={() => (mostrarNuevo = !mostrarNuevo)}>{$t.admin.roles.nuevoRol}</Button>
		</div>

		{#if mostrarNuevo}
			<form onsubmit={crear} class="form">
				<TextField label={$t.admin.roles.nombre} bind:value={nombreNuevo} required />
				<div class="field">
					<label for="permisos-nuevo">{$t.admin.roles.permisos}</label>
					<textarea id="permisos-nuevo" bind:value={permisosNuevo} rows="3"></textarea>
				</div>
				<Button type="submit" variant="primary" loading={creando}>{$t.admin.comun.crear}</Button>
			</form>
		{/if}

		<Table
			columnas={[
				{ key: 'nombre', header: $t.admin.roles.nombre },
				{ key: 'permisos', header: $t.admin.roles.colPermisos }
			]}
			filas={roles}
			claveFila={(f) => f.id}
			vacio={$t.admin.roles.sinRoles}
			seleccionadaId={editandoId}
			onSeleccionar={empezarEdicion}
		>
			{#snippet fila(rol)}
				<td>{rol.name}</td>
				<td class="secundario">{rol.permissions.join(', ') || '—'}</td>
			{/snippet}
		</Table>

		{#if editandoId}
			<form onsubmit={guardarEdicion} class="form detalle">
				<div class="field">
					<label for="permisos-editar">{$t.admin.roles.permisos}</label>
					<textarea id="permisos-editar" bind:value={permisosEditar} rows="3"></textarea>
				</div>
				<Button type="submit" variant="primary" loading={guardandoEdicion}>{$t.admin.comun.guardar}</Button>
			</form>
		{/if}
	{/if}
</Card>

<style>
	h1 {
		margin: 0 0 var(--space-6) 0;
		font-size: var(--text-2xl);
		color: var(--text-primary);
	}
	.cabecera {
		margin-bottom: var(--space-4);
	}
	.form {
		display: flex;
		flex-direction: column;
		max-width: 24rem;
		margin-bottom: var(--space-4);
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-4);
	}
	.field {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		margin-bottom: var(--space-4);
	}
	label {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		font-weight: 500;
	}
	textarea {
		background: var(--bg-base);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
		color: var(--text-primary);
		font-family: var(--font-mono);
		margin-bottom: var(--space-2);
	}
	.secundario {
		color: var(--text-muted);
		font-size: var(--text-sm);
	}
	.detalle {
		margin-top: var(--space-4);
		border-top: 1px solid var(--border-color);
		padding-top: var(--space-4);
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
	}
</style>
