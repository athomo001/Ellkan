<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-20: panel de administración — nav secundaria propia dentro del
	// AppShell (`(app)/+layout.svelte` ya resuelve guard de sesión + nav
	// principal + auto-bloqueo). Carga como bundle separado automáticamente
	// (code-splitting por ruta de SvelteKit) — la mayoría de las sesiones de
	// un usuario no-admin nunca visitan `/admin/*`, no pagan su peso.
	//
	// Guard de admin: **UX, no seguridad** — cada endpoint ya exige
	// `AdminUser`/`AuditorUser` server-side (04-seguridad-y-amenazas.md,
	// BWN-08-001: ningún flag de permiso cacheado en cliente es fuente de
	// verdad). Acá sólo se evita mostrar una pantalla que va a fallar: si
	// `esAdmin` (resuelto una sola vez en `(app)/+layout.svelte`, mismo
	// store que decide si el nav principal muestra el link) es `false`, se
	// manda de vuelta a `/vault` sin disparar un segundo `GET /admin/roles`.
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import type { Snippet } from 'svelte';
	import { esAdmin } from '$lib/state/session';
	import { t } from '$lib/i18n';

	let { children }: { children: Snippet } = $props();

	$effect(() => {
		if ($esAdmin === false) goto('/vault');
	});

	const secciones = $derived([
		{ href: '/admin/users', label: $t.admin.nav.usuarios },
		{ href: '/admin/roles', label: $t.admin.nav.roles },
		{ href: '/admin/groups', label: $t.admin.nav.grupos },
		{ href: '/admin/audit-log', label: $t.admin.nav.auditoria },
		{ href: '/admin/reports', label: $t.admin.nav.reportes },
		{ href: '/admin/policies/mfa', label: $t.admin.nav.politicaMfa },
		{ href: '/admin/policies/password', label: $t.admin.nav.politicaPassword },
		{ href: '/admin/policies/retention', label: $t.admin.nav.politicaRetencion },
		{ href: '/admin/policies/account-recovery', label: $t.admin.nav.politicaRecovery },
		{ href: '/admin/policies/emergency-access', label: $t.admin.nav.politicaEmergencia },
		{ href: '/admin/policies/device-approval', label: $t.admin.nav.politicaDispositivo },
		{ href: '/admin/policies/export', label: $t.admin.nav.politicaExport },
		{ href: '/admin/smtp', label: $t.admin.nav.smtp },
		{ href: '/admin/sso', label: $t.admin.nav.sso },
		{ href: '/admin/scim', label: $t.admin.nav.scim },
		{ href: '/admin/directory-sync', label: $t.admin.nav.directorySync },
		{ href: '/admin/metadata-keys', label: $t.admin.nav.metadataKeys }
	]);
</script>

{#if $esAdmin === true}
	<div class="admin">
		<nav>
			<ul>
				{#each secciones as seccion (seccion.href)}
					<li>
						<a href={seccion.href} class:activo={page.url.pathname === seccion.href}>{seccion.label}</a>
					</li>
				{/each}
			</ul>
		</nav>
		<div class="contenido">
			{@render children()}
		</div>
	</div>
{/if}

<style>
	.admin {
		display: grid;
		grid-template-columns: 14rem 1fr;
		gap: var(--space-6);
	}
	nav {
		border-right: 1px solid var(--border-color);
		padding-right: var(--space-4);
	}
	ul {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: 2px;
	}
	a {
		display: block;
		padding: var(--space-2) var(--space-3);
		border-radius: var(--radius-sm);
		color: var(--text-secondary);
		font-size: var(--text-sm);
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
	.contenido {
		min-width: 0;
	}
</style>
