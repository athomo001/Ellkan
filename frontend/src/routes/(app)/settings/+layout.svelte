<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-01/F-30: "Mi cuenta" — nav secundaria propia, mismo patrón exacto
	// que `(app)/admin/+layout.svelte`. Antes Perfil/Avatar/Claves/
	// Contraseña/Token vivían apretados en una sola página con scroll largo
	// (`/settings/profile`), y Preferencias/Seguridad eran dos entradas de
	// nav aparte aunque son la misma idea ("configuración de esta cuenta") —
	// ahora las 7 son secciones de un solo lugar, cada una su propia ruta.
	import { page } from '$app/state';
	import type { Snippet } from 'svelte';
	import { t } from '$lib/i18n';

	let { children }: { children: Snippet } = $props();

	const secciones = $derived([
		{ href: '/settings/profile', label: $t.settingsProfile.perfilTitulo },
		{ href: '/settings/avatar', label: $t.settingsProfile.avatarTitulo },
		{ href: '/settings/keys', label: $t.settingsProfile.clavesTitulo },
		{ href: '/settings/passphrase', label: $t.settingsProfile.passphraseTitulo },
		{ href: '/settings/token', label: $t.settingsProfile.tokenTitulo },
		{ href: '/settings/preferences', label: $t.appShell.preferencias },
		{ href: '/settings/security', label: $t.appShell.seguridad }
	]);
</script>

<div class="settings">
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

<style>
	.settings {
		display: grid;
		grid-template-columns: 12rem 1fr;
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
