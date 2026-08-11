<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// Módulo 1 (RBAC granular, inspirado en Passbolt): matriz visual de
	// permisos agrupada por categoría — reemplaza el textarea de permisos en
	// texto libre de antes (obligaba a "aprender de memoria" los strings de
	// permiso). Sólo `groups.create` tiene enforcement real en el backend
	// (`Permisos de API`); el resto son gates de UI (`Permisos de UI`, mismo
	// criterio que Passbolt: en una arquitectura zero-knowledge el servidor
	// no puede distinguir "leer para mostrarle al usuario" de "leer para
	// re-encriptar al editar", así que "puede previsualizar/copiar" sólo
	// puede aplicarse del lado del cliente).
	//
	// A diferencia de la captura de referencia (2 columnas fijas
	// Administrador/User), acá las columnas son dinámicas — una por cada rol
	// que exista, incluidos los custom que se creen desde esta misma página.
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import { rolesApi, type Rol } from '$lib/api/admin';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let cargando = $state(true);
	let error = $state<string | undefined>();
	let roles = $state<Rol[]>([]);
	/** `role.id` con un `PUT` en curso — evita doble-click mientras guarda. */
	let guardando = $state<string | undefined>();

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
	let creando = $state(false);

	async function crear(e: SubmitEvent) {
		e.preventDefault();
		creando = true;
		error = undefined;
		try {
			await rolesApi.crear(nombreNuevo, []);
			nombreNuevo = '';
			mostrarNuevo = false;
			await cargar();
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			creando = false;
		}
	}

	interface FilaMatriz {
		permiso: string;
		label: string;
	}
	interface CategoriaMatriz {
		label: string;
		filas: FilaMatriz[];
	}
	interface SeccionMatriz {
		label: string;
		categorias: CategoriaMatriz[];
	}

	// Catálogo curado — sólo permisos que un componente real del código
	// consume hoy (ver `spec/11-diseno-passbolt-avanzado.md`, módulo 1). No
	// se descubre dinámicamente del catálogo abierto de Postgres: la UI sólo
	// tiene sentido para los permisos que algo en la app realmente chequea.
	const secciones = $derived<SeccionMatriz[]>([
		{
			label: $t.admin.roles.matriz.seccionApi,
			categorias: [
				{
					label: $t.admin.roles.matriz.categoriaGestionGrupos,
					filas: [{ permiso: 'groups.create', label: $t.admin.roles.matriz.filaCrearGrupo }]
				}
			]
		},
		{
			label: $t.admin.roles.matriz.seccionUi,
			categorias: [
				{
					label: $t.admin.roles.matriz.categoriaImportExport,
					filas: [
						{ permiso: 'import.use', label: $t.admin.roles.matriz.filaImportar },
						{ permiso: 'export.use', label: $t.admin.roles.matriz.filaExportar }
					]
				},
				{
					label: $t.admin.roles.matriz.categoriaContrasena,
					filas: [
						{ permiso: 'password.preview', label: $t.admin.roles.matriz.filaPrevisualizar },
						{ permiso: 'password.copy', label: $t.admin.roles.matriz.filaCopiar }
					]
				},
				{
					label: $t.admin.roles.matriz.categoriaOrganizacion,
					filas: [{ permiso: 'folders.use', label: $t.admin.roles.matriz.filaUsarCarpetas }]
				},
				{
					label: $t.admin.roles.matriz.categoriaCompartiendo,
					filas: [{ permiso: 'folder.share', label: $t.admin.roles.matriz.filaCompartirCarpetas }]
				}
			]
		}
	]);

	function esComodin(rol: Rol): boolean {
		return rol.permissions.includes('*');
	}

	async function alternar(rol: Rol, permiso: string, permitir: boolean) {
		if (esComodin(rol)) return;
		const nuevos = permitir ? [...rol.permissions, permiso] : rol.permissions.filter((p) => p !== permiso);
		guardando = rol.id;
		error = undefined;
		try {
			const actualizado = await rolesApi.actualizarPermisos(rol.id, nuevos);
			roles = roles.map((r) => (r.id === rol.id ? actualizado : r));
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			guardando = undefined;
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
				<Button type="submit" variant="primary" loading={creando}>{$t.admin.comun.crear}</Button>
			</form>
		{/if}

		{#if roles.length === 0}
			<p>{$t.admin.roles.sinRoles}</p>
		{:else}
			<div class="tabla-scroll">
				<table class="matriz">
					<thead>
						<tr>
							<th class="col-permiso"></th>
							{#each roles as rol (rol.id)}
								<th class="col-rol">{rol.name}</th>
							{/each}
						</tr>
					</thead>
					<tbody>
						{#each secciones as seccion (seccion.label)}
							<tr class="fila-seccion">
								<td colspan={roles.length + 1}>{seccion.label}</td>
							</tr>
							{#each seccion.categorias as categoria (categoria.label)}
								<tr class="fila-categoria">
									<td colspan={roles.length + 1}>{categoria.label}</td>
								</tr>
								{#each categoria.filas as fila (fila.permiso)}
									<tr>
										<td class="col-permiso">{fila.label}</td>
										{#each roles as rol (rol.id)}
											<td class="col-rol">
												<select
													value={esComodin(rol) || rol.permissions.includes(fila.permiso) ? 'permitir' : 'denegar'}
													disabled={esComodin(rol) || guardando === rol.id}
													title={esComodin(rol) ? $t.admin.roles.matriz.comodinHint : undefined}
													onchange={(e) => alternar(rol, fila.permiso, e.currentTarget.value === 'permitir')}
												>
													<option value="permitir">{$t.admin.roles.matriz.permitir}</option>
													<option value="denegar">{$t.admin.roles.matriz.denegar}</option>
												</select>
											</td>
										{/each}
									</tr>
								{/each}
							{/each}
						{/each}
					</tbody>
				</table>
			</div>
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
		gap: var(--space-3);
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
	}
	.tabla-scroll {
		overflow-x: auto;
	}
	.matriz {
		border-collapse: collapse;
		width: 100%;
		font-size: var(--text-sm);
	}
	.matriz th,
	.matriz td {
		padding: var(--space-2) var(--space-3);
		border-bottom: 1px solid var(--border-color);
		text-align: left;
		white-space: nowrap;
	}
	.col-permiso {
		min-width: 16rem;
		color: var(--text-primary);
	}
	.col-rol {
		min-width: 10rem;
	}
	thead .col-rol {
		color: var(--text-secondary);
		font-weight: 600;
	}
	.fila-seccion td {
		font-weight: 700;
		color: var(--text-primary);
		background: var(--bg-overlay);
		padding-top: var(--space-3);
	}
	.fila-categoria td {
		font-weight: 500;
		color: var(--text-secondary);
	}
	.matriz select {
		background: var(--bg-base);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-1) var(--space-2);
		color: var(--text-primary);
		width: 100%;
	}
	.matriz select:disabled {
		opacity: 0.6;
	}
</style>
