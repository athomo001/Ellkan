<!-- Autor: Athan Espinoza -->
<script lang="ts">
	import { onMount } from 'svelte';
	import { enModoEscritorio } from '$lib/tauri/conectar';

	// Estado reactivo para determinar si estamos en el entorno nativo de escritorio Tauri.
	let esDesktop = $state(false);
	let estaMaximizado = $state(false);

	onMount(async () => {
		esDesktop = enModoEscritorio();
		if (esDesktop) {
			try {
				const { getCurrentWindow } = await import('@tauri-apps/api/window');
				const appWindow = getCurrentWindow();
				estaMaximizado = await appWindow.isMaximized();

				// Escuchador de cambios de tamaño para sincronizar el icono de maximizar/restaurar.
				appWindow.onResized(async () => {
					estaMaximizado = await appWindow.isMaximized();
				});
			} catch {
				// En entornos donde la API no responda, mantenemos el comportamiento por defecto.
			}
		}
	});

	// La barra es `fixed`, pero reserva su lugar en el flujo (espaciador): se publica su altura
	// real en `--titlebar-h` para que los layouts que se dimensionan contra la
	// ventana (`100vh`) la resten. Sin esto el documento mide `100vh + 36px` y
	// lo pegado al fondo — el pie del menú lateral, con "Cerrar sesión" — queda
	// corrido hacia abajo, sin su margen. Acción de Svelte para que se limpie
	// solo cuando la barra desaparece.
	function reservarAltura(nodo: HTMLElement) {
		const raiz = document.documentElement;
		raiz.style.setProperty('--titlebar-h', `${nodo.offsetHeight}px`);
		return {
			destroy() {
				raiz.style.removeProperty('--titlebar-h');
			}
		};
	}

	// Función para minimizar la ventana al área de tareas o bandeja del sistema.
	async function minimizar() {
		try {
			const { getCurrentWindow } = await import('@tauri-apps/api/window');
			await getCurrentWindow().minimize();
		} catch (error) {
			console.error('Error al minimizar ventana:', error);
		}
	}

	// Función para alternar entre tamaño normal y maximizado.
	async function alternarMaximizar() {
		try {
			const { getCurrentWindow } = await import('@tauri-apps/api/window');
			await getCurrentWindow().toggleMaximize();
		} catch (error) {
			console.error('Error al maximizar ventana:', error);
		}
	}

	// Función para cerrar la ventana (en modo escritorio minimiza a la bandeja del sistema).
	async function cerrar() {
		try {
			const { getCurrentWindow } = await import('@tauri-apps/api/window');
			await getCurrentWindow().close();
		} catch (error) {
			console.error('Error al cerrar ventana:', error);
		}
	}
</script>

{#if esDesktop}
	<header class="titlebar" data-tauri-drag-region use:reservarAltura>
		<!-- Área izquierda: Isotipo, Nombre de la aplicación y Bóveda activa -->
		<div class="titlebar-left" data-tauri-drag-region>
			<span class="logo-badge" data-tauri-drag-region>
				<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
					<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
				</svg>
			</span>
			<span class="app-title" data-tauri-drag-region>Ellkan</span>
			<span class="separator" data-tauri-drag-region>—</span>
			<span class="vault-title" data-tauri-drag-region>Bóveda Principal (Local)</span>
			<span class="status-indicator" title="Bóveda local cifrada (SQLite WAL)" data-tauri-drag-region></span>
		</div>

		<!-- Área derecha: Botones nativos estilizados de control de ventana -->
		<div class="window-controls">
			<button class="win-btn" onclick={minimizar} title="Minimizar" aria-label="Minimizar">
				<svg width="11" height="11" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.2">
					<path d="M2 6h8" />
				</svg>
			</button>

			<button class="win-btn" onclick={alternarMaximizar} title={estaMaximizado ? "Restaurar" : "Maximizar"} aria-label={estaMaximizado ? "Restaurar" : "Maximizar"}>
				{#if estaMaximizado}
					<svg width="11" height="11" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.2">
						<path d="M3.5 3.5h5v5h-5z" />
						<path d="M5.5 3.5V2h5v5H9" />
					</svg>
				{:else}
					<svg width="11" height="11" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.2">
						<rect x="2" y="2" width="8" height="8" rx="1" />
					</svg>
				{/if}
			</button>

			<button class="win-btn close-btn" onclick={cerrar} title="Cerrar a la bandeja" aria-label="Cerrar">
				<svg width="11" height="11" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.2">
					<path d="M2.5 2.5l7 7M9.5 2.5l-7 7" />
				</svg>
			</button>
		</div>
	</header>
	<!-- La barra es `fixed` (no ocupa lugar): este bloque reserva su altura en el flujo. -->
	<div class="titlebar-espacio" aria-hidden="true"></div>
{/if}

<style>
	.titlebar {
		height: 36px;
		background: var(--bg-overlay);
		border-bottom: 1px solid var(--border-color);
		display: flex;
		justify-content: space-between;
		align-items: center;
		user-select: none;
		/* `fixed` y no `sticky`: un sticky sólo se queda pegado dentro de su
		   contenedor (el `body`, que mide `100%` de la ventana), así que al
		   bajar por una página larga la barra se iba con el contenido y sin
		   ella no hay de dónde arrastrar la ventana. */
		position: fixed;
		top: 0;
		left: 0;
		right: 0;
		z-index: 9999;
		font-size: var(--text-xs);
		color: var(--text-primary);
	}

	.titlebar-espacio {
		height: 36px;
	}

	.titlebar-left {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		padding-left: var(--space-3);
		height: 100%;
		flex: 1;
	}

	.logo-badge {
		color: var(--accent-primary);
		display: flex;
		align-items: center;
	}

	.app-title {
		font-weight: 700;
		color: var(--text-primary);
		letter-spacing: 0.02em;
	}

	.separator {
		color: var(--border-color);
	}

	.vault-title {
		color: var(--text-secondary);
	}

	.status-indicator {
		width: 7px;
		height: 7px;
		border-radius: 50%;
		background: var(--success);
		box-shadow: 0 0 6px var(--success);
		margin-left: var(--space-1);
	}

	.window-controls {
		display: flex;
		height: 100%;
	}

	.win-btn {
		width: 44px;
		height: 100%;
		display: flex;
		align-items: center;
		justify-content: center;
		background: transparent;
		border: none;
		color: var(--text-secondary);
		cursor: pointer;
		transition: background 0.15s ease, color 0.15s ease;
	}

	.win-btn:hover {
		background: var(--border-color);
		color: var(--text-primary);
	}

	.close-btn:hover {
		background: var(--danger);
		color: #ffffff;
	}
</style>
