<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-30/F-31/F-39: `/me/preferences` real — locale, tema, minutos de
	// limpieza de portapapeles y auto-bloqueo. El campo de auto-bloqueo en sí
	// (temporizador que efectivamente bloquea la UI) es F-39, checklist
	// aparte — acá sólo se persiste la preferencia.
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import { preferencias } from '$lib/state/session';
	import { guardarPreferencias, aplicarTema } from '$lib/api/preferences';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let locale = $state($preferencias.locale);
	let theme = $state($preferencias.theme);
	let clipboardClearMinutes = $state(String($preferencias.clipboardClearMinutes));
	let autoLockMinutes = $state(
		$preferencias.autoLockMinutes === null ? '' : String($preferencias.autoLockMinutes)
	);

	let guardando = $state(false);
	let error = $state<string | undefined>();
	let guardado = $state(false);

	async function guardar(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;
		guardado = false;
		guardando = true;
		try {
			const nueva = await guardarPreferencias({
				locale: locale as 'en' | 'es',
				theme: theme as 'light' | 'dark',
				clipboardClearMinutes: Number(clipboardClearMinutes),
				autoLockMinutes: autoLockMinutes === '' ? null : Number(autoLockMinutes)
			});
			aplicarTema(nueva.theme);
			guardado = true;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.settingsPreferences.error;
		} finally {
			guardando = false;
		}
	}
</script>

<svelte:head>
	<title>{$t.settingsPreferences.titulo} — Ellkan</title>
</svelte:head>

<h1>{$t.settingsPreferences.titulo}</h1>

<Card>
	<form onsubmit={guardar}>
		<div class="field">
			<label for="locale">{$t.settingsPreferences.idioma}</label>
			<select id="locale" bind:value={locale}>
				<option value="es">{$t.settingsPreferences.espanol}</option>
				<option value="en">{$t.settingsPreferences.ingles}</option>
			</select>
		</div>

		<div class="field">
			<label for="theme">{$t.settingsPreferences.tema}</label>
			<select id="theme" bind:value={theme}>
				<option value="dark">{$t.settingsPreferences.oscuro}</option>
				<option value="light">{$t.settingsPreferences.claro}</option>
			</select>
		</div>

		<div class="field">
			<label for="clipboard">{$t.settingsPreferences.portapapeles}</label>
			<input id="clipboard" type="number" min="0" bind:value={clipboardClearMinutes} />
		</div>

		<div class="field">
			<label for="autolock">{$t.settingsPreferences.autoBloqueo}</label>
			<input id="autolock" type="number" min="1" bind:value={autoLockMinutes} />
		</div>

		{#if error}<p class="error">{error}</p>{/if}
		{#if guardado}<p class="ok">{$t.settingsPreferences.guardado}</p>{/if}
		<Button type="submit" variant="primary" loading={guardando}>{$t.settingsPreferences.guardar}</Button>
	</form>
</Card>

<style>
	h1 {
		margin: 0 0 var(--space-6) 0;
		font-size: var(--text-2xl);
		color: var(--text-primary);
	}
	form {
		display: flex;
		flex-direction: column;
		max-width: 24rem;
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
	select,
	input {
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
		color: var(--text-primary);
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
	}
	.ok {
		color: var(--success);
		font-size: var(--text-sm);
	}
</style>
