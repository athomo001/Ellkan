<!-- Autor: Athan Espinoza -->
<script lang="ts">
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import { smtpConfigApi } from '$lib/api/admin';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let cargando = $state(true);
	let guardando = $state(false);
	let error = $state<string | undefined>();
	let guardado = $state(false);
	let configurado = $state(false);

	let host = $state('');
	let port = $state('587');
	let fromAddress = $state('');
	let tls = $state(true);
	let username = $state('');
	// Nunca se precarga con la contraseña real (write-only, F-02/Parte A) —
	// en blanco significa "no cambiarla".
	let passwordNueva = $state('');
	let borrarPassword = $state(false);

	let destinatarioPrueba = $state('');
	let probando = $state(false);
	let resultadoPrueba = $state<string | undefined>();
	let errorPrueba = $state<string | undefined>();

	async function cargar() {
		cargando = true;
		error = undefined;
		try {
			const c = await smtpConfigApi.obtener();
			configurado = c.configurado;
			host = c.host ?? '';
			port = c.port !== null ? String(c.port) : '587';
			fromAddress = c.from_address ?? '';
			tls = c.tls;
			username = c.username ?? '';
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			cargando = false;
		}
	}

	onMount(cargar);

	async function guardar(e: SubmitEvent) {
		e.preventDefault();
		error = undefined;
		guardado = false;
		guardando = true;
		try {
			const c = await smtpConfigApi.actualizar({
				host,
				port: Number(port),
				from_address: fromAddress,
				tls,
				username: username.trim() ? username : null,
				password: borrarPassword ? '' : passwordNueva ? passwordNueva : null
			});
			configurado = c.configurado;
			passwordNueva = '';
			borrarPassword = false;
			guardado = true;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			guardando = false;
		}
	}

	async function probar(e: SubmitEvent) {
		e.preventDefault();
		errorPrueba = undefined;
		resultadoPrueba = undefined;
		probando = true;
		try {
			const r = await smtpConfigApi.probar(destinatarioPrueba);
			resultadoPrueba = r.status;
		} catch (err) {
			errorPrueba = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			probando = false;
		}
	}
</script>

<h1>{$t.admin.smtp.titulo}</h1>
<Card>
	{#if cargando}
		<p>{$t.admin.comun.cargando}</p>
	{:else}
		<p class="estado" class:ok={configurado} class:advertencia={!configurado}>
			{configurado ? $t.admin.smtp.estadoConfigurado : $t.admin.smtp.estadoNoConfigurado}
		</p>
		<form onsubmit={guardar}>
			<TextField label={$t.admin.smtp.host} bind:value={host} required />
			<TextField label={$t.admin.smtp.puerto} type="number" bind:value={port} required />
			<TextField label={$t.admin.smtp.remitente} type="email" bind:value={fromAddress} required />
			<label class="check"><input type="checkbox" bind:checked={tls} /> {$t.admin.smtp.tls}</label>
			<TextField label={$t.admin.smtp.usuario} bind:value={username} autocomplete="off" />
			<TextField
				label={$t.admin.smtp.contrasena}
				type="password"
				bind:value={passwordNueva}
				hint={$t.admin.smtp.contrasenaHint}
				autocomplete="new-password"
				disabled={borrarPassword}
			/>
			<label class="check">
				<input type="checkbox" bind:checked={borrarPassword} />
				{$t.admin.smtp.contrasenaBorrar}
			</label>
			{#if error}<p class="error">{error}</p>{/if}
			{#if guardado}<p class="ok-msg">{$t.admin.comun.guardado}</p>{/if}
			<Button type="submit" variant="primary" loading={guardando}>{$t.admin.comun.guardar}</Button>
		</form>
	{/if}
</Card>

{#if !cargando && configurado}
	<Card>
		<h2>{$t.admin.smtp.probarTitulo}</h2>
		<p class="ayuda">{$t.admin.smtp.probarAyuda}</p>
		<form class="probar" onsubmit={probar}>
			<TextField label={$t.admin.smtp.probarDestinatario} type="email" bind:value={destinatarioPrueba} required />
			<Button type="submit" variant="secondary" loading={probando}>{$t.admin.smtp.probarBoton}</Button>
		</form>
		{#if probando}<p class="ayuda">{$t.admin.smtp.probarEnviando}</p>{/if}
		{#if errorPrueba}<p class="error">{errorPrueba}</p>{/if}
		{#if resultadoPrueba === 'enviado'}<p class="ok-msg">{$t.admin.smtp.probarResultadoEnviado}</p>{/if}
		{#if resultadoPrueba === 'fallido'}<p class="error">{$t.admin.smtp.probarResultadoFallido}</p>{/if}
		{#if resultadoPrueba === 'pendiente'}<p class="ayuda">{$t.admin.smtp.probarResultadoPendiente}</p>{/if}
	</Card>
{/if}

<style>
	h1 {
		margin: 0 0 var(--space-6) 0;
		font-size: var(--text-2xl);
		color: var(--text-primary);
	}
	form {
		display: flex;
		flex-direction: column;
		max-width: 28rem;
	}
	.estado {
		font-size: var(--text-sm);
		padding: var(--space-3);
		border-radius: var(--radius-sm);
		margin: 0 0 var(--space-4) 0;
		border: 1px solid var(--border-color);
	}
	.estado.ok {
		color: var(--success);
	}
	.estado.advertencia {
		color: var(--danger);
	}
	.check {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		margin-bottom: var(--space-4);
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
	}
	.ok-msg {
		color: var(--success);
		font-size: var(--text-sm);
	}
	h2 {
		margin: 0 0 var(--space-2) 0;
		font-size: var(--text-lg);
		color: var(--text-primary);
	}
	.ayuda {
		margin: 0 0 var(--space-4) 0;
		font-size: var(--text-sm);
		color: var(--text-secondary);
	}
	.probar {
		display: flex;
		align-items: flex-end;
		gap: var(--space-3);
		max-width: 28rem;
	}
	.probar :global(.field) {
		flex: 1;
	}
</style>
