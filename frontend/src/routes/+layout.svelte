<script lang="ts">
	import '$lib/styles/base.css';
	import { preferencias } from '$lib/state/session';
	import { aplicarTema } from '$lib/api/preferences';
	import { openUrl } from '@tauri-apps/plugin-opener';

	import TitleBar from '$lib/components/TitleBar.svelte';
	import CerrarAppDialogo from '$lib/components/CerrarAppDialogo.svelte';
	import { goto } from '$app/navigation';
	import { enlacePendiente } from '$lib/tauri/sistema';

	let { children } = $props();

	// El backend emite `cierre-solicitado` cuando el usuario cierra la ventana
	// y la preferencia es "preguntar" — ver `$lib/tauri/ventana.ts`.
	let mostrarCierre = $state(false);

	// Enlace `ellkan://…` (la app se abrió por él, o ya estaba abierta): el shell
	// lo valida y deja una ruta de la bóveda pendiente; acá se navega a ella.
	async function irAlEnlacePendiente() {
		try {
			const ruta = await enlacePendiente();
			if (ruta) await goto(ruta);
		} catch {
			/* sin enlace pendiente legible: no hay nada que hacer */
		}
	}

	// Aplica el tema guardado (persiste en disco, sobrevive logout — F-30)
	// desde antes de cualquier login: la pantalla de login también debe
	// respetar la preferencia elegida en una sesión anterior.
	$effect(() => {
		aplicarTema($preferencias.theme);
	});

	// Modo escritorio (Tauri): el WebView no abre `<a target="_blank">` en el
	// navegador del sistema por sí solo (a diferencia de una pestaña normal
	// de navegador) — hallazgo real de uso: clickear la URI de un recurso en
	// el Vault no hacía nada. Un solo listener acá, en el layout raíz que
	// envuelve TODA la app (login incluido), cubre cualquier link externo
	// presente o futuro sin tener que tocar cada página una por una.
	$effect(() => {
		if (typeof window === 'undefined' || !('__TAURI_INTERNALS__' in window)) return;

		function alClickear(e: MouseEvent) {
			const anchor = (e.target as HTMLElement)?.closest?.('a');
			const href = anchor?.getAttribute('href');
			if (!href || !/^https?:\/\//i.test(href)) return;
			e.preventDefault();
			openUrl(href).catch(() => {
				/* si falla (protocolo no soportado por el SO, etc.) no hay
				 * nada más que hacer acá — el link simplemente no abre. */
			});
		}

		document.addEventListener('click', alClickear);
		return () => document.removeEventListener('click', alClickear);
	});

	import { clavesDesbloqueadas } from '$lib/state/session';

	// Eventos nativos de Tauri (Bandeja y Atajo Global F-45, F-51)
	$effect(() => {
		if (typeof window === 'undefined' || !('__TAURI_INTERNALS__' in window)) return;
		let desuscribirBloqueo: (() => void) | undefined;
		let desuscribirAtajo: (() => void) | undefined;
		let desuscribirCierre: (() => void) | undefined;
		let desuscribirEnlace: (() => void) | undefined;

		irAlEnlacePendiente();

		import('@tauri-apps/api/event').then(({ listen }) => {
			listen('enlace-profundo', () => {
				irAlEnlacePendiente();
			}).then((unlisten) => {
				desuscribirEnlace = unlisten;
			});

			listen('cierre-solicitado', () => {
				mostrarCierre = true;
			}).then((unlisten) => {
				desuscribirCierre = unlisten;
			});

			listen('bloquear-boveda', () => {
				clavesDesbloqueadas.set(null);
			}).then((unlisten) => {
				desuscribirBloqueo = unlisten;
			});

			listen('atajo-global-activado', () => {
				const inputBusqueda = document.querySelector<HTMLInputElement>(
					'input[type="search"], input[placeholder*="Buscar"]'
				);
				inputBusqueda?.focus();
			}).then((unlisten) => {
				desuscribirAtajo = unlisten;
			});
		});

		return () => {
			desuscribirBloqueo?.();
			desuscribirAtajo?.();
			desuscribirCierre?.();
			desuscribirEnlace?.();
		};
	});
</script>

<TitleBar />
{@render children()}
{#if mostrarCierre}
	<CerrarAppDialogo onCerrar={() => (mostrarCierre = false)} />
{/if}
