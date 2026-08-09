<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-43: autodiagnóstico admin — cada fila se resuelve sola en el
	// backend (nivel ok/advertencia/error) y acá sólo se traduce `id` + los
	// parámetros del check a un mensaje (F-31, nunca texto libre desde el
	// backend) y a una sugerencia de reparación si aplica.
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import { systemStatusApi, type Check, type GrupoChecks, type NivelCheck } from '$lib/api/admin';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let cargando = $state(true);
	let error = $state<string | undefined>();
	let grupos = $state<GrupoChecks[]>([]);

	async function cargar() {
		cargando = true;
		error = undefined;
		try {
			grupos = await systemStatusApi.obtener();
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.estadoSistema.error;
		} finally {
			cargando = false;
		}
	}
	onMount(cargar);

	function categoriaLabel(categoria: GrupoChecks['categoria']): string {
		const e = $t.admin.estadoSistema;
		return (
			{
				entorno: e.categoriaEntorno,
				base_datos: e.categoriaBaseDatos,
				correo: e.categoriaCorreo,
				integraciones: e.categoriaIntegraciones,
				seguridad: e.categoriaSeguridad
			} satisfies Record<GrupoChecks['categoria'], string>
		)[categoria];
	}

	function nivelLabel(nivel: NivelCheck): string {
		const e = $t.admin.estadoSistema;
		return { ok: e.nivelOk, advertencia: e.nivelAdvertencia, error: e.nivelError }[nivel];
	}

	function mensaje(check: Check): string {
		const e = $t.admin.estadoSistema;
		switch (check.id) {
			case 'version_app':
				return e.versionApp(check.version);
			case 'db_ping':
				return check.nivel === 'ok' ? e.dbPingOk : e.dbPingError;
			case 'db_migraciones':
				return check.fallidas > 0 ? e.dbMigracionesError(check.fallidas) : e.dbMigracionesOk(check.aplicadas);
			case 'smtp_configurado':
				return check.configurado ? e.smtpConfiguradoOk : e.smtpConfiguradoAdvertencia;
			case 'correo_backlog':
				if (check.fallidos > 0) return e.correoBacklogError(check.fallidos);
				if (check.pendientes > 0) return e.correoBacklogAdvertencia(check.pendientes);
				return e.correoBacklogOk;
			case 'sso_configurado':
				return check.configurado ? e.ssoConfiguradoSi : e.ssoConfiguradoNo;
			case 'directory_sync_configurado':
				if (!check.configurado) return e.directorySyncConfiguradoNo;
				if (!check.ultima_sincronizacion) return e.directorySyncNuncaSincronizado;
				return `${e.directorySyncConfiguradoSi} ${e.ultimaSincronizacion(new Date(check.ultima_sincronizacion).toLocaleString())}`;
			case 'metadata_key_rotacion':
				return check.claves_activas > 1 ? e.metadataRotacionAdvertencia(check.claves_activas) : e.metadataRotacionOk;
		}
	}

	function sugerencia(check: Check): string | undefined {
		const e = $t.admin.estadoSistema;
		if (check.nivel === 'ok') return undefined;
		switch (check.id) {
			case 'db_ping':
				return e.dbPingSugerencia;
			case 'db_migraciones':
				return e.dbMigracionesSugerencia;
			case 'smtp_configurado':
				return e.smtpConfiguradoSugerencia;
			case 'correo_backlog':
				return e.correoBacklogSugerencia;
			case 'directory_sync_configurado':
				return e.directorySyncSugerencia;
			case 'metadata_key_rotacion':
				return e.metadataRotacionSugerencia;
			default:
				return undefined;
		}
	}
</script>

<h1>{$t.admin.estadoSistema.titulo}</h1>
<p class="hint">{$t.admin.estadoSistema.hint}</p>

{#if error}
	<p class="error">{error}</p>
{:else if !cargando}
	{#each grupos as grupo (grupo.categoria)}
		<div class="grupo">
			<Card>
				<h2>{categoriaLabel(grupo.categoria)}</h2>
				<ul>
					{#each grupo.checks as check (check.id)}
						<li>
							<span class="fila">
								<span class="punto nivel-{check.nivel}" title={nivelLabel(check.nivel)}></span>
								<span class="mensaje">{mensaje(check)}</span>
							</span>
							{#if sugerencia(check)}
								<p class="sugerencia">{sugerencia(check)}</p>
							{/if}
						</li>
					{/each}
				</ul>
			</Card>
		</div>
	{/each}
{/if}

<style>
	h1 {
		margin: 0 0 var(--space-2) 0;
		font-size: var(--text-2xl);
		color: var(--text-primary);
	}
	.hint {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-6) 0;
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
	}
	.grupo {
		margin-bottom: var(--space-4);
	}
	h2 {
		margin: 0 0 var(--space-3) 0;
		font-size: var(--text-base);
		color: var(--text-primary);
	}
	ul {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.fila {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.punto {
		flex: 0 0 auto;
		width: 0.6rem;
		height: 0.6rem;
		border-radius: 50%;
	}
	.nivel-ok {
		background: var(--success);
	}
	.nivel-advertencia {
		background: var(--warning);
	}
	.nivel-error {
		background: var(--danger);
	}
	.mensaje {
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.sugerencia {
		margin: 0 0 0 calc(0.6rem + var(--space-2));
		font-size: var(--text-xs);
		color: var(--text-muted);
	}
</style>
