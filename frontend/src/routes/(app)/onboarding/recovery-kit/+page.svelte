<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// Recovery kit: paso obligatorio, no saltable — mismo criterio "sin
	// gracia" que MFA obligatorio. Cubre tres casos con un solo componente
	// (`GenerarRecoveryKit`): onboarding nuevo (`motivo=nuevo`, default),
	// cuenta preexistente que nunca configuró uno, y post-recuperación por
	// kit (`motivo=rotacion`, el kit anterior ya no sirve). El hook que
	// manda para acá vive en `(anon)/login/+page.svelte::completarSesion`.
	import { goto } from '$app/navigation';
	import { page } from '$app/state';
	import Card from '$lib/components/Card.svelte';
	import GenerarRecoveryKit from '$lib/components/GenerarRecoveryKit.svelte';
	import { t } from '$lib/i18n';

	const esRotacion = $derived(page.url.searchParams.get('motivo') === 'rotacion');
	const mensaje = $derived(esRotacion ? $t.recoveryKit.introRotacion : $t.recoveryKit.introOnboarding);

	function alGenerar() {
		goto('/vault');
	}
</script>

<svelte:head>
	<title>{$t.recoveryKit.tituloOnboarding} — Ellkan</title>
</svelte:head>

<Card>
	<h1>{esRotacion ? $t.recoveryKit.tituloRotacion : $t.recoveryKit.tituloOnboarding}</h1>
	<GenerarRecoveryKit {mensaje} onGenerado={alGenerar} />
</Card>

<style>
	h1 {
		margin: 0 0 var(--space-2) 0;
		font-size: var(--text-2xl);
		color: var(--text-primary);
	}
</style>
