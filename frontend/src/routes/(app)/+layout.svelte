<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// AppShell (07-frontend-web.md §3): guard de sesión válida + nav lateral
	// + contenido a ancho completo — layout compartido por todas las rutas
	// autenticadas (`/vault`, `/settings/*`). El guard es client-side puro
	// (el id de sesión vive en `sessionStorage`, F-04 — sobrevive un F5 de
	// la misma pestaña, se pierde al cerrarla; la clave privada en sí sigue
	// sólo en memoria, nunca sobrevive un reload).
	import { onMount } from 'svelte';
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import type { Snippet } from 'svelte';
	import { sesion, preferencias, esAdmin, permisos } from '$lib/state/session';
	import { cargarPreferencias, alternarTema as alternarTemaLocal, guardarPreferencias } from '$lib/api/preferences';
	import { cerrarSesion } from '$lib/crypto/identity';
	import { limpiarStoresEn } from '$lib/state/declarative-store';
	import { perfilApi, permisosApi, obtenerAvatarUrl, type Perfil } from '$lib/api/profile';
	import { ApiError } from '$lib/api/client';
	import Button from '$lib/components/Button.svelte';
	import LockOverlay from '$lib/components/LockOverlay.svelte';
	import { t } from '$lib/i18n';

	let { children }: { children: Snippet } = $props();

	let verificando = $state(true);

	$effect(() => {
		if (!$sesion.sessionId) {
			goto('/login');
			return;
		}
		verificando = false;
	});

	// Las preferencias reales del servidor pisan el default local apenas
	// hay sesión — evita que un cambio hecho desde otro cliente (u otra
	// pestaña) quede desactualizado en esta.
	$effect(() => {
		if ($sesion.sessionId) {
			cargarPreferencias().catch(() => {
				/* si falla, el default local ya declarado en session.ts sigue sirviendo */
			});
		}
	});

	// Se resuelve una sola vez por sesión — ver comentario de `esAdmin`/`permisos`
	// en `$lib/state/session.ts`. Antes esto probaba `GET /admin/roles` y miraba
	// si daba 403 (hack); `GET /me/permissions` da el conjunto real y `esAdmin`
	// queda como un derivado (`'*'` presente) en vez de una llamada aparte.
	$effect(() => {
		if ($sesion.sessionId && $esAdmin === null) {
			permisosApi
				.mias()
				.then((lista) => {
					const conjunto = new Set(lista);
					permisos.set(conjunto);
					esAdmin.set(conjunto.has('*'));
				})
				.catch((err) => {
					// Hallazgo real de uso: esto degradaba a "no admin, sin
					// permisos" ante CUALQUIER falla — incluido un `429` de
					// rate limit tras F5 seguidos, que no significa que el
					// usuario haya perdido sus permisos. Sólo un `401` real
					// (la sesión efectivamente ya no vale) es una respuesta
					// con la que vale la pena quedarse; cualquier otra causa
					// deja `esAdmin` en `null` — sigue sin mostrar nav de
					// admin en esta carga puntual, pero la próxima recarga
					// vuelve a intentarlo en vez de quedar mal-cacheado en
					// "false" para siempre.
					if (err instanceof ApiError && err.status === 401) esAdmin.set(false);
				});
		}
	});

	// Nombre/avatar para el pie del nav — antes sólo mostraba el email.
	// `perfil`/`avatarUrl` viven sólo en memoria de este layout (nunca en
	// un store persistente): un dato de refresco barato, no vale la pena
	// declararlo como store compartido para un solo consumidor.
	let perfil = $state<Perfil | undefined>();
	let avatarUrl = $state<string | null>(null);
	onMount(() => {
		perfilApi.obtener().then((p) => (perfil = p)).catch(() => {});
		obtenerAvatarUrl().then((u) => (avatarUrl = u)).catch(() => {});
	});

	// F-39: auto-bloqueo por inactividad. `bloqueado` sólo tapa el
	// contenido — `limpiarStoresEn('lock')` limpia `clavesDesbloqueadas`
	// (crypto ya desenvuelto), nunca `sesion` (`clearOn` de ese store ya no
	// incluye 'lock', ver comentario en `state/session.ts`), así que la
	// sesión HTTP sigue viva mientras está bloqueado.
	let bloqueado = $state(false);
	let ultimaActividadMs = Date.now();

	function marcarActividad() {
		ultimaActividadMs = Date.now();
	}

	$effect(() => {
		const eventos = ['mousemove', 'keydown', 'click', 'scroll', 'touchstart'] as const;
		for (const evento of eventos) window.addEventListener(evento, marcarActividad, { passive: true });

		const intervalo = setInterval(() => {
			const minutos = $preferencias.autoLockMinutes;
			if (minutos === null || bloqueado) return;
			if (Date.now() - ultimaActividadMs >= minutos * 60_000) {
				bloqueado = true;
				limpiarStoresEn('lock');
			}
		}, 15_000);

		return () => {
			for (const evento of eventos) window.removeEventListener(evento, marcarActividad);
			clearInterval(intervalo);
		};
	});

	function alDesbloquear() {
		bloqueado = false;
		marcarActividad();
	}

	// Los toggles rápidos (acá y en el nav) sólo aplican local al toque —
	// para que el cambio no se pierda al loguearse en otro dispositivo,
	// una vez logueado también se sincroniza a `/me/preferences` (fire and
	// forget: si falla, el default de la próxima sesión sigue siendo el
	// local, no rompe nada).
	function sincronizarPreferencias() {
		guardarPreferencias($preferencias).catch(() => {
			/* el cambio local ya se aplicó — la sync es best-effort */
		});
	}

	function alternarTema(e: MouseEvent) {
		// `onAplicado`, no código después del llamado — con la View Transition
		// API el cambio de store no es sincrónico, ver comentario en
		// `$lib/api/preferences.ts::alternarTema`.
		alternarTemaLocal($preferencias.theme, e, sincronizarPreferencias);
	}

	function alternarIdioma() {
		preferencias.update((p) => ({ ...p, locale: p.locale === 'es' ? 'en' : 'es' }));
		sincronizarPreferencias();
	}

	async function salir() {
		await cerrarSesion();
		goto('/login');
	}

	// Íconos por sección — sin esto, un nav colapsado no tendría nada que
	// mostrar salvo texto cortado ilegible.
	const ICONOS = {
		vault: 'M16.5 10.5V6.75a4.5 4.5 0 1 0-9 0v3.75m-.75 11.25h10.5a2.25 2.25 0 0 0 2.25-2.25v-6.75a2.25 2.25 0 0 0-2.25-2.25H6.75a2.25 2.25 0 0 0-2.25 2.25v6.75a2.25 2.25 0 0 0 2.25 2.25Z',
		perfil:
			'M17.982 18.725A7.488 7.488 0 0 0 12 15.75a7.488 7.488 0 0 0-5.982 2.975m11.963 0a9 9 0 1 0-11.963 0m11.963 0A8.966 8.966 0 0 1 12 21a8.966 8.966 0 0 1-5.982-2.275M15 9.75a3 3 0 1 1-6 0 3 3 0 0 1 6 0Z',
		compartir:
			'M7.217 10.907a2.25 2.25 0 1 0 0 2.186m0-2.186c.18.324.283.696.283 1.093s-.103.77-.283 1.093m0-2.186 9.566-5.314m-9.566 7.5 9.566 5.314m0 0a2.25 2.25 0 1 0 3.935 2.186 2.25 2.25 0 0 0-3.935-2.186Zm0-12.814a2.25 2.25 0 1 0 3.933-2.185 2.25 2.25 0 0 0-3.933 2.185Z',
		admin:
			'M15 19.128a9.38 9.38 0 0 0 2.625.372 9.337 9.337 0 0 0 4.121-.952 4.125 4.125 0 0 0-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 0 1 8.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0 1 11.964-3.07M12 6.375a3.375 3.375 0 1 1-6.75 0 3.375 3.375 0 0 1 6.75 0Zm8.25 2.25a2.625 2.625 0 1 1-5.25 0 2.625 2.625 0 0 1 5.25 0Z'
	};

	// "Mi cuenta" agrupa Perfil/Avatar/Claves/Contraseña/Token/Preferencias/
	// Seguridad — antes eran 3 entradas de nav separadas (Mi perfil,
	// Preferencias, Seguridad) para configuración que es, en el fondo, de
	// la misma persona (`(app)/settings/+layout.svelte` tiene la nav
	// secundaria real). Exportar/Importar se sacó del todo de acá — ahora
	// vive dentro de Vault, donde están los recursos que exporta.
	const RUTAS_MI_CUENTA = [
		'/settings/profile',
		'/settings/avatar',
		'/settings/keys',
		'/settings/passphrase',
		'/settings/token',
		'/settings/preferences',
		'/settings/security'
	];
	function esRutaActiva(enlace: { href: string }, pathname: string): boolean {
		if (enlace.href === '/settings/profile') return RUTAS_MI_CUENTA.some((r) => pathname.startsWith(r));
		return pathname.startsWith(enlace.href);
	}

	const enlaces = $derived([
		{ href: '/vault', label: $t.appShell.vault, icono: ICONOS.vault },
		{ href: '/settings/profile', label: $t.appShell.miCuenta, icono: ICONOS.perfil },
		{ href: '/settings/external-shares', label: $t.settingsExternalShares.titulo, icono: ICONOS.compartir },
		...($esAdmin ? [{ href: '/admin', label: $t.appShell.administracion, icono: ICONOS.admin }] : [])
	]);

	// Colapsable (ahorra espacio horizontal) — persiste en localStorage
	// directo, no en `preferencias`/`/me/preferences`: es puramente de
	// layout de esta pantalla, no una preferencia de cuenta que tenga
	// sentido sincronizar entre dispositivos (un monitor angosto en un
	// dispositivo no implica nada sobre otro).
	let colapsado = $state(typeof localStorage !== 'undefined' && localStorage.getItem('ellkan-nav-colapsado') === '1');
	function toggleColapsado() {
		colapsado = !colapsado;
		localStorage.setItem('ellkan-nav-colapsado', colapsado ? '1' : '0');
	}
</script>

{#if !verificando}
	<div class="shell" class:colapsado>
		<nav>
			<div class="marca-fila">
				<div class="marca">
					<img src="/ellkan-icon-mark.png" alt="" width="24" height="24" />
					{#if !colapsado}<span>Ellkan</span>{/if}
				</div>
				<button
					type="button"
					class="toggle-colapso"
					onclick={toggleColapsado}
					title={colapsado ? $t.appShell.expandirNav : $t.appShell.colapsarNav}
				>
					<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" width="16" height="16">
						{#if colapsado}
							<path stroke-linecap="round" stroke-linejoin="round" d="M8.25 4.5l7.5 7.5-7.5 7.5" />
						{:else}
							<path stroke-linecap="round" stroke-linejoin="round" d="M15.75 19.5L8.25 12l7.5-7.5" />
						{/if}
					</svg>
				</button>
			</div>
			<ul>
				{#each enlaces as enlace (enlace.href)}
					<li>
						<a href={enlace.href} class:activo={esRutaActiva(enlace, page.url.pathname)} title={colapsado ? enlace.label : ''}>
							<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" width="18" height="18">
								<path stroke-linecap="round" stroke-linejoin="round" d={enlace.icono} />
							</svg>
							{#if !colapsado}<span>{enlace.label}</span>{/if}
						</a>
					</li>
				{/each}
			</ul>
			<div class="pie">
				<div class="controles-topbar">
					<button type="button" class="toggle-tema" onclick={(e) => alternarTema(e)} title={$t.appShell.cambiarTema}>
						{#if $preferencias.theme === 'light'}
							<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" width="18" height="18">
								<path stroke-linecap="round" stroke-linejoin="round" d="M12 3v2.25m6.364.386-1.591 1.591M21 12h-2.25m-.386 6.364-1.591-1.591M12 18.75V21m-4.773-4.227-1.591 1.591M3 12h2.25m-.386-6.364 1.591 1.591M12 7.5a4.5 4.5 0 1 0 0 9 4.5 4.5 0 0 0 0-9Z" />
							</svg>
						{:else}
							<svg xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke-width="1.5" stroke="currentColor" width="18" height="18">
								<path stroke-linecap="round" stroke-linejoin="round" d="M21.752 15.002A9.72 9.72 0 0 1 18 15.75c-5.385 0-9.75-4.365-9.75-9.75 0-1.33.266-2.597.748-3.752A9.753 9.753 0 0 0 3 11.25C3 16.635 7.365 21 12.75 21a9.753 9.753 0 0 0 9.002-5.998Z" />
							</svg>
						{/if}
					</button>
					<button
						type="button"
						class="toggle-idioma"
						onclick={alternarIdioma}
						title={$preferencias.locale === 'es' ? 'Switch to English' : 'Cambiar a Español'}
					>
						{$preferencias.locale}
					</button>
				</div>
				<a class="cuenta" href="/settings/profile" title={$sesion.email ?? ''}>
					{#if avatarUrl}
						<img class="avatar" src={avatarUrl} alt="" />
					{:else}
						<span class="avatar avatar-vacio">{(perfil?.display_name ?? $sesion.email ?? '?').charAt(0).toUpperCase()}</span>
					{/if}
					{#if !colapsado}
						<span class="cuenta-texto">
							<span class="nombre">{perfil?.display_name ?? $sesion.email}</span>
							{#if perfil}<span class="correo">{perfil.email}</span>{/if}
						</span>
					{/if}
				</a>
				<Button variant="ghost" onclick={salir}>{colapsado ? '⏻' : $t.appShell.cerrarSesion}</Button>
			</div>
		</nav>
		<main>
			{@render children()}
		</main>
	</div>
	{#if bloqueado}
		<LockOverlay email={$sesion.email ?? ''} onDesbloqueado={alDesbloquear} />
	{/if}
{/if}

<style>
	.shell {
		display: grid;
		grid-template-columns: var(--nav-width) 1fr;
		min-height: 100vh;
		background: var(--bg-base);
		transition: grid-template-columns 0.15s;
	}
	.shell.colapsado {
		grid-template-columns: 4rem 1fr;
	}
	nav {
		display: flex;
		flex-direction: column;
		border-right: 1px solid var(--border-color);
		background: var(--bg-raised);
		padding: var(--space-6) var(--space-4);
		overflow-x: hidden;
		overflow-y: auto;
		/* Hallazgo real de uso, 2026-08-12: sin `position: sticky` + altura
		   fija, este nav es una celda de grid que se estira para igualar la
		   altura de `main` (`.shell` no fija `height`, sólo `min-height`) —
		   en una página larga (ej. la nav secundaria de /admin, bastante más
		   alta que los 4 links de este nav) el pie con el botón de "cerrar
		   sesión" terminaba muy por debajo del viewport, a mitad de la lista
		   de la nav secundaria vecina en vez de pegado abajo del todo. */
		position: sticky;
		top: 0;
		height: 100vh;
	}
	.marca-fila {
		display: flex;
		align-items: center;
		justify-content: space-between;
		margin-bottom: var(--space-8);
	}
	.colapsado .marca-fila {
		justify-content: center;
		flex-direction: column;
		gap: var(--space-3);
	}
	.marca {
		display: flex;
		align-items: center;
		gap: var(--space-2);
	}
	.toggle-colapso {
		display: flex;
		align-items: center;
		justify-content: center;
		background: none;
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-1);
		color: var(--text-secondary);
		cursor: pointer;
		flex-shrink: 0;
	}
	.toggle-colapso:hover {
		color: var(--text-primary);
		border-color: var(--accent-primary);
	}
	.controles-topbar {
		display: flex;
		align-items: center;
		justify-content: center;
		gap: var(--space-2);
	}
	.colapsado .controles-topbar {
		flex-direction: column;
	}
	.toggle-tema {
		display: flex;
		align-items: center;
		justify-content: center;
		background: none;
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-1);
		color: var(--text-secondary);
		cursor: pointer;
	}
	.toggle-tema:hover {
		color: var(--text-primary);
		border-color: var(--accent-primary);
	}
	.toggle-idioma {
		background: none;
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-1) var(--space-2);
		font-size: var(--text-xs);
		font-weight: 700;
		text-transform: uppercase;
		letter-spacing: 0.04em;
		color: var(--text-secondary);
		cursor: pointer;
	}
	.toggle-idioma:hover {
		color: var(--text-primary);
		border-color: var(--accent-primary);
	}
	.marca img {
		display: block;
		border-radius: var(--radius-sm);
	}
	.marca span {
		font-size: var(--text-xl);
		font-weight: 700;
		background: var(--gradient-brand);
		-webkit-background-clip: text;
		background-clip: text;
		color: transparent;
	}
	ul {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		flex: 1;
	}
	a {
		display: flex;
		align-items: center;
		gap: var(--space-3);
		padding: var(--space-2) var(--space-3);
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		font-size: var(--text-sm);
		font-weight: 500;
		white-space: nowrap;
	}
	a svg {
		flex-shrink: 0;
	}
	.colapsado a {
		justify-content: center;
		padding: var(--space-2);
	}
	a:hover {
		background: var(--bg-overlay);
		color: var(--text-primary);
	}
	a.activo {
		background: var(--bg-overlay);
		color: var(--text-primary);
		box-shadow: inset 2px 0 0 var(--accent-primary);
	}
	.pie {
		display: flex;
		flex-direction: column;
		align-items: stretch;
		gap: var(--space-2);
		border-top: 1px solid var(--border-color);
		padding-top: var(--space-4);
	}
	.colapsado .pie {
		align-items: center;
	}
	.cuenta {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		min-width: 0;
		color: var(--text-primary);
		text-decoration: none;
		border-radius: var(--radius-sm);
		padding: var(--space-1);
	}
	.cuenta:hover {
		background: var(--bg-overlay);
	}
	.avatar {
		width: 1.75rem;
		height: 1.75rem;
		border-radius: 50%;
		object-fit: cover;
		flex-shrink: 0;
	}
	.avatar-vacio {
		display: flex;
		align-items: center;
		justify-content: center;
		background: var(--bg-overlay);
		color: var(--text-muted);
		font-size: var(--text-xs);
		font-weight: 600;
	}
	.cuenta-texto {
		display: flex;
		flex-direction: column;
		min-width: 0;
	}
	.nombre {
		font-size: var(--text-sm);
		color: var(--text-primary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.correo {
		font-size: var(--text-xs);
		color: var(--text-muted);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	main {
		padding: var(--space-8);
		max-width: var(--content-max-width);
		overflow-x: auto;
	}
</style>
