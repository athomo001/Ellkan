<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-36 (#134): la bóveda del titular vista por su contacto de emergencia,
	// con el acceso ya concedido. Sólo lectura (ver y copiar; ni editar ni
	// compartir). Se descifra acá con las privadas que el titular selló para
	// mí; el servidor audita cada apertura. Los secretos viven sólo en esta
	// pantalla: al salir se descartan.
	import { onMount } from 'svelte';
	import { get } from 'svelte/store';
	import { page } from '$app/state';
	import { goto } from '$app/navigation';
	import Card from '#lib/components/Card.svelte';
	import Button from '#lib/components/Button.svelte';
	import TextField from '#lib/components/TextField.svelte';
	import { evaluarFortaleza } from '#lib/crypto/passwordStrength.svelte';
	import { abrirBovedaDelTitular, tomarControlDeLaCuenta, type BovedaDelTitular } from '#lib/crypto/emergencia';
	import { clavesDesbloqueadas, preferencias } from '#lib/state/session';
	import { copiarConLimpieza } from '#lib/clipboard';
	import { ApiError } from '#lib/api/client';
	import { t } from '#lib/i18n';

	let boveda = $state<BovedaDelTitular | undefined>();
	let cargando = $state(true);
	let error = $state<string | undefined>();
	let visibles = $state<Record<string, boolean>>({});
	let copiadoId = $state<string | null>(null);

	const titulo = $derived(
		boveda
			? $t.settingsEmergency.bovedaTitulo.replace('{nombre}', boveda.titular.display_name || boveda.titular.email)
			: $t.settingsEmergency.titulo
	);

	onMount(() => {
		void (async () => {
			const claves = get(clavesDesbloqueadas);
			if (!claves) {
				error = get(t).settingsEmergency.bovedaSinClaves;
				cargando = false;
				return;
			}
			try {
				boveda = await abrirBovedaDelTitular(page.params.id ?? '', claves);
			} catch (err) {
				error = err instanceof ApiError ? err.message : get(t).settingsEmergency.error;
			} finally {
				cargando = false;
			}
		})();
		return () => {
			// Nada de esto se guarda: al salir se suelta la referencia.
			boveda = undefined;
		};
	});

	// Nivel `takeover`.
	let nueva = $state('');
	let confirmacion = $state('');
	let tomando = $state(false);
	let errorTakeover = $state<string | undefined>();
	let takeoverListo = $state(false);

	async function tomarControl(e: SubmitEvent) {
		e.preventDefault();
		errorTakeover = undefined;
		const textos = get(t).settingsEmergency;
		if (nueva !== confirmacion) {
			errorTakeover = textos.takeoverNoCoinciden;
			return;
		}
		if (evaluarFortaleza(nueva).score < 3) {
			errorTakeover = textos.takeoverDebil;
			return;
		}
		const claves = get(clavesDesbloqueadas);
		if (!claves) {
			errorTakeover = textos.bovedaSinClaves;
			return;
		}
		tomando = true;
		try {
			await tomarControlDeLaCuenta(page.params.id ?? '', nueva, claves);
			takeoverListo = true;
			nueva = '';
			confirmacion = '';
		} catch (err) {
			errorTakeover = err instanceof ApiError ? err.message : textos.error;
		} finally {
			tomando = false;
		}
	}

	async function copiar(id: string, texto: string) {
		await copiarConLimpieza(texto, $preferencias.clipboardClearMinutes);
		copiadoId = id;
		setTimeout(() => {
			if (copiadoId === id) copiadoId = null;
		}, 1500);
	}
</script>

<Card>
	<h1>{titulo}</h1>
	<p class="hint">{$t.settingsEmergency.bovedaIntro}</p>
	<Button variant="secondary" onclick={() => goto('/settings/emergency')}>{$t.settingsEmergency.bovedaVolver}</Button>
</Card>

<Card>
	{#if cargando}
		<p class="hint">{$t.settingsEmergency.cargando}</p>
	{:else if error}
		<p class="error" role="alert">{error}</p>
	{:else if boveda}
		{#if boveda.sinAbrir > 0}
			<p class="hint">{$t.settingsEmergency.bovedaSinAbrir.replace('{n}', String(boveda.sinAbrir))}</p>
		{/if}
		{#if boveda.recursos.length === 0}
			<p class="hint">{$t.settingsEmergency.bovedaVacia}</p>
		{:else}
			<ul class="lista">
				{#each boveda.recursos as r (r.id)}
					<li>
						<strong>{r.nombre || r.uri || r.id}</strong>
						{#if r.usuario}
							<span class="secundario">{$t.settingsEmergency.bovedaUsuario}: {r.usuario}</span>
						{/if}
						{#if r.uri}
							<span class="secundario">{$t.settingsEmergency.bovedaSitio}: {r.uri}</span>
						{/if}
						{#if r.secreto.password}
							<div class="secreto">
								<code>{visibles[r.id] ? r.secreto.password : '••••••••••••'}</code>
								<Button variant="secondary" onclick={() => (visibles[r.id] = !visibles[r.id])}>
									{visibles[r.id] ? $t.settingsEmergency.bovedaOcultar : $t.settingsEmergency.bovedaMostrar}
								</Button>
								<Button variant="secondary" onclick={() => copiar(r.id, r.secreto.password)}>
									{copiadoId === r.id ? $t.settingsEmergency.bovedaCopiado : $t.settingsEmergency.bovedaCopiar}
								</Button>
							</div>
						{/if}
						{#if r.secreto.notes && visibles[r.id]}
							<span class="secundario notas">{$t.settingsEmergency.bovedaNotas}: {r.secreto.notes}</span>
						{/if}
					</li>
				{/each}
			</ul>
		{/if}
	{/if}
</Card>

{#if boveda?.nivel === 'takeover'}
	<Card>
		<h2>{$t.settingsEmergency.takeoverTitulo}</h2>
		<p class="hint">{$t.settingsEmergency.takeoverIntro}</p>
		{#if takeoverListo}
			<p class="hint" role="status">{$t.settingsEmergency.takeoverListo}</p>
		{:else}
			<form onsubmit={tomarControl}>
				<TextField label={$t.settingsEmergency.takeoverNueva} type="password" bind:value={nueva} autocomplete="new-password" required />
				<TextField
					label={$t.settingsEmergency.takeoverConfirmar}
					type="password"
					bind:value={confirmacion}
					autocomplete="new-password"
					required
				/>
				{#if errorTakeover}
					<p class="error" role="alert">{errorTakeover}</p>
				{/if}
				<Button type="submit" variant="danger" loading={tomando}>{$t.settingsEmergency.takeoverBoton}</Button>
			</form>
		{/if}
	</Card>
{/if}

<style>
	h2 {
		margin: 0 0 var(--space-2) 0;
		font-size: var(--text-lg);
		color: var(--text-primary);
	}
	form {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		max-width: 24rem;
	}
	h1 {
		margin: 0 0 var(--space-2) 0;
		font-size: var(--text-2xl);
		color: var(--text-primary);
	}
	.hint {
		color: var(--text-secondary);
		font-size: var(--text-sm);
		margin: 0 0 var(--space-4) 0;
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
	}
	:global(.card) + :global(.card) {
		margin-top: var(--space-4);
	}
	.lista {
		list-style: none;
		margin: 0;
		padding: 0;
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.lista li {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		padding: var(--space-3);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-md);
	}
	.secundario {
		color: var(--text-secondary);
		font-size: var(--text-sm);
	}
	.notas {
		white-space: pre-wrap;
	}
	.secreto {
		display: flex;
		gap: var(--space-2);
		align-items: center;
		flex-wrap: wrap;
	}
	code {
		font-family: var(--font-mono, monospace);
	}
</style>
