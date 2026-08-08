<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// AppShell (07-frontend-web.md §3): guard de sesión válida + nav lateral
	// + contenido a ancho completo — layout compartido por todas las rutas
	// autenticadas (`/vault`, `/settings/*`). El guard es client-side puro
	// (la sesión vive sólo en memoria, F-04, nunca en una cookie que un
	// `+layout.server.ts` pudiera leer) — un refresh de página pierde la
	// sesión por diseño, igual que ya pasa hoy sin AppShell.
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import type { Snippet } from 'svelte';
	import { sesion, preferencias, esAdmin } from '$lib/state/session';
	import { cargarPreferencias } from '$lib/api/preferences';
	import { cerrarSesion } from '$lib/crypto/identity';
	import { limpiarStoresEn } from '$lib/state/declarative-store';
	import { rolesApi } from '$lib/api/admin';
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

	// Se resuelve una sola vez por sesión — ver comentario de `esAdmin` en
	// `$lib/state/session.ts`.
	$effect(() => {
		if ($sesion.sessionId && $esAdmin === null) {
			rolesApi
				.listar()
				.then(() => esAdmin.set(true))
				.catch((err) => esAdmin.set(!(err instanceof ApiError && err.status === 403)));
		}
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

	async function salir() {
		await cerrarSesion();
		goto('/login');
	}

	const enlaces = $derived([
		{ href: '/vault', label: $t.appShell.vault },
		{ href: '/settings/preferences', label: $t.appShell.preferencias },
		{ href: '/settings/security', label: $t.appShell.seguridad },
		{ href: '/settings/export-import', label: $t.exportImport.titulo },
		...($esAdmin ? [{ href: '/admin', label: $t.appShell.administracion }] : [])
	]);
</script>

{#if !verificando}
	<div class="shell">
		<nav>
			<div class="marca">Ellkan</div>
			<ul>
				{#each enlaces as enlace (enlace.href)}
					<li>
						<a href={enlace.href} class:activo={page.url.pathname.startsWith(enlace.href)}>
							{enlace.label}
						</a>
					</li>
				{/each}
			</ul>
			<div class="pie">
				<span class="email" title={$sesion.email ?? ''}>{$sesion.email}</span>
				<Button variant="ghost" onclick={salir}>{$t.appShell.cerrarSesion}</Button>
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
	}
	nav {
		display: flex;
		flex-direction: column;
		border-right: 1px solid var(--border-color);
		background: var(--bg-raised);
		padding: var(--space-6) var(--space-4);
	}
	.marca {
		font-size: var(--text-xl);
		font-weight: 700;
		margin-bottom: var(--space-8);
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
		display: block;
		padding: var(--space-2) var(--space-3);
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		font-size: var(--text-sm);
		font-weight: 500;
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
		gap: var(--space-2);
		border-top: 1px solid var(--border-color);
		padding-top: var(--space-4);
	}
	.email {
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
