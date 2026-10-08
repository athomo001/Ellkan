<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-30/F-31/F-39: `/me/preferences` real — locale, tema, minutos de
	// limpieza de portapapeles y auto-bloqueo. El campo de auto-bloqueo en sí
	// (temporizador que efectivamente bloquea la UI) es F-39, checklist
	// aparte — acá sólo se persiste la preferencia.
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import { preferencias } from '$lib/state/session';
	import { guardarPreferencias } from '$lib/api/preferences';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';
	import {
		preferenciasLectura,
		normalizarLectura,
		FUENTES_LECTURA,
		ESCALA_MIN,
		ESCALA_MAX,
		ESCALA_PASO,
		type PreferenciasLectura
	} from '$lib/state/lectura';

	// Accesibilidad / lectura: se aplica al instante y queda en este
	// dispositivo, sin botón de guardar (no pasa por el servidor).
	const lectura = $derived(normalizarLectura($preferenciasLectura));
	function cambiarLectura(cambio: Partial<PreferenciasLectura>) {
		preferenciasLectura.set(normalizarLectura({ ...lectura, ...cambio }));
	}

	// Mientras se arrastra sólo se mueve este valor; la página cambia de tamaño
	// al soltar. Si cambiara en cada movimiento, el slider se re-acomoda bajo el
	// mouse y el valor salta a una punta.
	let escalaArrastrando = $state<number | undefined>();
	const escalaVisible = $derived(escalaArrastrando ?? lectura.escala);

	// Idioma y tema se cambian con los toggles del nav (icono arriba) — no
	// se duplican acá para no tener dos lugares para lo mismo. Este form
	// sigue mandando el valor actual de los dos en el `PUT` (la API espera
	// el objeto completo), sólo no deja editarlos desde acá.
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
			await guardarPreferencias({
				locale: $preferencias.locale,
				theme: $preferencias.theme,
				clipboardClearMinutes: Number(clipboardClearMinutes),
				autoLockMinutes: autoLockMinutes === '' ? null : Number(autoLockMinutes)
			});
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

<Card>
	<h2>{$t.settingsPreferences.lectura.titulo}</h2>
	<p class="hint">{$t.settingsPreferences.lectura.hint}</p>
	<div class="formulario">
		<label class="opcion">
			<input type="checkbox" checked={lectura.activa} onchange={(e) => cambiarLectura({ activa: e.currentTarget.checked })} />
			{$t.settingsPreferences.lectura.activar}
		</label>

		<div class="field">
			<label for="fuente-lectura">{$t.settingsPreferences.lectura.fuente}</label>
			<select
				id="fuente-lectura"
				value={lectura.fuente}
				onchange={(e) => cambiarLectura({ fuente: e.currentTarget.value as PreferenciasLectura['fuente'] })}
			>
				{#each FUENTES_LECTURA as f (f)}
					<option value={f}>{$t.settingsPreferences.lectura.fuentes[f]}</option>
				{/each}
			</select>
		</div>

		<div class="field">
			<label for="espaciado-lectura">{$t.settingsPreferences.lectura.espaciado}</label>
			<select
				id="espaciado-lectura"
				value={lectura.espaciado}
				onchange={(e) => cambiarLectura({ espaciado: e.currentTarget.value as PreferenciasLectura['espaciado'] })}
			>
				<option value="normal">{$t.settingsPreferences.lectura.normal}</option>
				<option value="amplio">{$t.settingsPreferences.lectura.amplio}</option>
			</select>
		</div>

		<div class="field">
			<label for="interlineado-lectura">{$t.settingsPreferences.lectura.interlineado}</label>
			<select
				id="interlineado-lectura"
				value={lectura.interlineado}
				onchange={(e) => cambiarLectura({ interlineado: e.currentTarget.value as PreferenciasLectura['interlineado'] })}
			>
				<option value="normal">{$t.settingsPreferences.lectura.normal}</option>
				<option value="amplio">{$t.settingsPreferences.lectura.amplio}</option>
			</select>
		</div>

		<div class="field">
			<label for="escala-lectura">{$t.settingsPreferences.lectura.tamano(escalaVisible)}</label>
			<input
				id="escala-lectura"
				type="range"
				min={ESCALA_MIN}
				max={ESCALA_MAX}
				step={ESCALA_PASO}
				value={escalaVisible}
				oninput={(e) => (escalaArrastrando = Number(e.currentTarget.value))}
				onchange={(e) => {
					cambiarLectura({ escala: Number(e.currentTarget.value) });
					escalaArrastrando = undefined;
				}}
			/>
		</div>

		<p class="muestra">{$t.settingsPreferences.lectura.muestra}</p>
		<p class="muestra secreto">0O lI1 rn m {'{}'} []</p>

		<div>
			<Button variant="ghost" onclick={() => preferenciasLectura.set(normalizarLectura(undefined))}>
				{$t.settingsPreferences.lectura.restablecer}
			</Button>
		</div>
	</div>
</Card>

<style>
	h1 {
		margin: 0 0 var(--space-6) 0;
		font-size: var(--text-2xl);
		color: var(--text-primary);
	}
	form,
	.formulario {
		display: flex;
		flex-direction: column;
		max-width: 24rem;
	}
	h2 {
		margin: 0 0 var(--space-2) 0;
		font-size: var(--text-lg);
	}
	.hint {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		margin: 0 0 var(--space-4) 0;
	}
	select {
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
		color: var(--text-primary);
	}
	input[type='range'] {
		padding: 0;
		border: none;
		background: none;
	}
	.opcion {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		margin-bottom: var(--space-4);
		font-size: var(--text-sm);
		color: var(--text-primary);
	}
	.opcion input {
		padding: 0;
	}
	.muestra {
		margin: 0 0 var(--space-2) 0;
		padding: var(--space-3);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
	}
	.muestra.secreto {
		font-family: var(--font-mono);
		margin-bottom: var(--space-4);
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
