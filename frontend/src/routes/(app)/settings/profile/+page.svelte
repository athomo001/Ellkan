<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-01: "Mi perfil" — 5 secciones independientes en una sola página,
	// mismo patrón que `settings/security` (varios Card relacionados, sin
	// nav anidado nuevo).
	import { onMount } from 'svelte';
	import { get } from 'svelte/store';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import { perfilApi, avatarApi, obtenerAvatarUrl, type Perfil } from '$lib/api/profile';
	import { cambiarPassphrase, cerrarSesion } from '$lib/crypto/identity';
	import { evaluarFortaleza } from '$lib/crypto/passwordStrength';
	import { bytesABase64 } from '$lib/crypto/b64';
	import { sesion, clavesDesbloqueadas } from '$lib/state/session';
	import { goto } from '$app/navigation';
	import {
		obtenerTokenSeguridad,
		generarTokenSeguridad,
		COLOR_HEX,
		type TokenSeguridad
	} from '$lib/state/securityToken';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	const email = $derived($sesion.email ?? '');

	// --- Perfil ---
	let cargandoPerfil = $state(true);
	let perfil = $state<Perfil | undefined>();
	let errorPerfil = $state<string | undefined>();

	onMount(async () => {
		try {
			perfil = await perfilApi.obtener();
		} catch (err) {
			errorPerfil = err instanceof ApiError ? err.message : get(t).settingsProfile.error;
		} finally {
			cargandoPerfil = false;
		}
	});

	// --- Avatar ---
	let avatarUrl = $state<string | null>(null);
	let archivoAvatar = $state<File | undefined>();
	let subiendoAvatar = $state(false);
	let errorAvatar = $state<string | undefined>();

	async function cargarAvatar() {
		try {
			avatarUrl = await obtenerAvatarUrl();
		} catch {
			/* sin avatar visible si esto falla, el resto de la página sigue */
		}
	}
	onMount(cargarAvatar);

	function alElegirAvatar(e: Event) {
		archivoAvatar = (e.target as HTMLInputElement).files?.[0];
		errorAvatar = undefined;
	}

	async function subirAvatar() {
		if (!archivoAvatar) return;
		errorAvatar = undefined;
		subiendoAvatar = true;
		try {
			const bytes = new Uint8Array(await archivoAvatar.arrayBuffer());
			await avatarApi.actualizar(bytesABase64(bytes), archivoAvatar.type);
			archivoAvatar = undefined;
			await cargarAvatar();
		} catch (err) {
			errorAvatar = err instanceof ApiError ? err.message : get(t).settingsProfile.avatarErrorSubir;
		} finally {
			subiendoAvatar = false;
		}
	}

	async function quitarAvatar() {
		errorAvatar = undefined;
		subiendoAvatar = true;
		try {
			await avatarApi.eliminar();
			avatarUrl = null;
		} catch (err) {
			errorAvatar = err instanceof ApiError ? err.message : get(t).settingsProfile.avatarErrorQuitar;
		} finally {
			subiendoAvatar = false;
		}
	}

	// --- Inspector de claves ---
	let fingerprintX25519 = $state<string | undefined>();
	let fingerprintEd25519 = $state<string | undefined>();
	$effect(() => {
		const claves = $clavesDesbloqueadas;
		if (!claves) {
			fingerprintX25519 = undefined;
			fingerprintEd25519 = undefined;
			return;
		}
		(async () => {
			fingerprintX25519 = bytesABase64(
				new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(claves.x25519Public)))
			).slice(0, 16);
			fingerprintEd25519 = bytesABase64(
				new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(claves.ed25519Public)))
			).slice(0, 16);
		})();
	});

	// --- Frase de contraseña ---
	let passphraseActual = $state('');
	let passphraseNueva = $state('');
	let passphraseConfirmacion = $state('');
	let cambiandoPassphrase = $state(false);
	let errorPassphrase = $state<string | undefined>();
	let passphraseListo = $state(false);
	const fortalezaNueva = $derived(evaluarFortaleza(passphraseNueva));
	const labelFortaleza = $derived(
		[
			get(t).fortalezaPassword.muyDebil,
			get(t).fortalezaPassword.debil,
			get(t).fortalezaPassword.aceptable,
			get(t).fortalezaPassword.fuerte,
			get(t).fortalezaPassword.muyFuerte
		][fortalezaNueva.score]
	);

	async function enviarCambioPassphrase(e: SubmitEvent) {
		e.preventDefault();
		errorPassphrase = undefined;
		if (passphraseNueva !== passphraseConfirmacion) {
			errorPassphrase = get(t).settingsProfile.passphraseErrorNoCoinciden;
			return;
		}
		if (fortalezaNueva.score < 3) {
			errorPassphrase = get(t).settingsProfile.passphraseErrorDebil;
			return;
		}
		cambiandoPassphrase = true;
		try {
			await cambiarPassphrase(email, passphraseActual, passphraseNueva);
			passphraseListo = true;
			// El cambio ya rotó `security_stamp` server-side — esta misma sesión
			// queda invalidada, así que se limpia el estado local y se manda a
			// login (no es un error, es el resultado esperado del cambio).
			setTimeout(async () => {
				await cerrarSesion().catch(() => {});
				goto('/login');
			}, 1500);
		} catch (err) {
			errorPassphrase =
				err instanceof ApiError || err instanceof Error
					? get(t).settingsProfile.passphraseErrorActual
					: get(t).settingsProfile.passphraseErrorGenerico;
		} finally {
			cambiandoPassphrase = false;
		}
	}

	// --- Token de seguridad ---
	let tokenSeguridad = $state<TokenSeguridad | null>(null);
	onMount(() => {
		if (email) tokenSeguridad = obtenerTokenSeguridad(email);
	});
	function aleatorizarToken() {
		if (!email) return;
		tokenSeguridad = generarTokenSeguridad(email);
	}
</script>

<svelte:head>
	<title>{$t.settingsProfile.titulo} — Ellkan</title>
</svelte:head>

<h1>{$t.settingsProfile.titulo}</h1>

<Card>
	<h2>{$t.settingsProfile.perfilTitulo}</h2>
	{#if cargandoPerfil}
		<p class="hint">{$t.settingsProfile.cargando}</p>
	{:else if errorPerfil}
		<p class="error">{errorPerfil}</p>
	{:else if perfil}
		<dl>
			<dt>{$t.settingsProfile.nombre}</dt>
			<dd>{perfil.display_name}</dd>
			<dt>{$t.settingsProfile.email}</dt>
			<dd>{perfil.email}</dd>
			<dt>{$t.settingsProfile.rol}</dt>
			<dd>{perfil.role}</dd>
			<dt>{$t.settingsProfile.creado}</dt>
			<dd>{new Date(perfil.created_at).toLocaleString()}</dd>
			<dt>{$t.settingsProfile.modificado}</dt>
			<dd>{new Date(perfil.updated_at).toLocaleString()}</dd>
		</dl>
	{/if}
</Card>

<Card>
	<h2>{$t.settingsProfile.avatarTitulo}</h2>
	<p class="hint">{$t.settingsProfile.avatarHint}</p>
	<div class="avatar-fila">
		{#if avatarUrl}
			<img class="avatar" src={avatarUrl} alt="" />
		{:else}
			<div class="avatar avatar-vacio">{(perfil?.display_name ?? '?').charAt(0).toUpperCase()}</div>
		{/if}
		<div class="avatar-acciones">
			<input type="file" accept="image/png,image/jpeg,image/webp" onchange={alElegirAvatar} />
			<div class="botones">
				<Button variant="secondary" onclick={subirAvatar} disabled={!archivoAvatar} loading={subiendoAvatar}>
					{$t.settingsProfile.avatarSubir}
				</Button>
				{#if avatarUrl}
					<Button variant="danger" onclick={quitarAvatar} loading={subiendoAvatar}>
						{$t.settingsProfile.avatarQuitar}
					</Button>
				{/if}
			</div>
		</div>
	</div>
	{#if errorAvatar}<p class="error">{errorAvatar}</p>{/if}
</Card>

<Card>
	<h2>{$t.settingsProfile.clavesTitulo}</h2>
	<p class="hint">{$t.settingsProfile.clavesHint}</p>
	{#if fingerprintX25519 && fingerprintEd25519}
		<dl>
			<dt>{$t.settingsProfile.clavesFingerprintX25519}</dt>
			<dd class="mono">{fingerprintX25519}</dd>
			<dt>{$t.settingsProfile.clavesFingerprintEd25519}</dt>
			<dd class="mono">{fingerprintEd25519}</dd>
			{#if perfil}
				<dt>{$t.settingsProfile.clavesCreadas}</dt>
				<dd>{new Date(perfil.keys_created_at).toLocaleString()}</dd>
			{/if}
		</dl>
	{:else}
		<p class="hint">{$t.settingsProfile.clavesBloqueadas}</p>
	{/if}
</Card>

<Card>
	<h2>{$t.settingsProfile.passphraseTitulo}</h2>
	<p class="hint">{$t.settingsProfile.passphraseHint}</p>
	{#if passphraseListo}
		<p class="ok">{$t.settingsProfile.passphraseListo}</p>
	{:else}
		<form onsubmit={enviarCambioPassphrase}>
			<TextField
				label={$t.settingsProfile.passphraseActual}
				type="password"
				bind:value={passphraseActual}
				autocomplete="current-password"
				required
			/>
			<TextField
				label={$t.settingsProfile.passphraseNueva}
				type="password"
				bind:value={passphraseNueva}
				autocomplete="new-password"
				required
			/>
			{#if passphraseNueva}
				<p class="fortaleza fortaleza-{fortalezaNueva.score}">{labelFortaleza}</p>
			{/if}
			<TextField
				label={$t.settingsProfile.passphraseConfirmar}
				type="password"
				bind:value={passphraseConfirmacion}
				autocomplete="new-password"
				required
			/>
			{#if errorPassphrase}<p class="error">{errorPassphrase}</p>{/if}
			<Button type="submit" variant="primary" loading={cambiandoPassphrase}>
				{$t.settingsProfile.passphraseCambiar}
			</Button>
		</form>
	{/if}
</Card>

<Card>
	<h2>{$t.settingsProfile.tokenTitulo}</h2>
	<p class="hint">{$t.settingsProfile.tokenHint}</p>
	{#if tokenSeguridad}
		<p class="token">
			<span class="punto-token" style:background={COLOR_HEX[tokenSeguridad.color]}></span>
			<strong>{tokenSeguridad.palabra}</strong>
		</p>
	{:else}
		<p class="hint">{$t.settingsProfile.tokenSinToken}</p>
	{/if}
	<Button variant="secondary" onclick={aleatorizarToken}>{$t.settingsProfile.tokenAleatorizar}</Button>
</Card>

<style>
	h1 {
		margin: 0 0 var(--space-6) 0;
		font-size: var(--text-2xl);
		color: var(--text-primary);
	}
	h2 {
		margin: 0 0 var(--space-2) 0;
		font-size: var(--text-lg);
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
	.ok {
		color: var(--success);
		font-size: var(--text-sm);
	}
	:global(.card) + :global(.card) {
		margin-top: var(--space-4);
	}
	form {
		display: flex;
		flex-direction: column;
		max-width: 24rem;
	}
	dl {
		display: grid;
		grid-template-columns: auto 1fr;
		gap: var(--space-1) var(--space-4);
		margin: 0;
	}
	dt {
		color: var(--text-secondary);
		font-size: var(--text-sm);
	}
	dd {
		margin: 0;
		color: var(--text-primary);
		font-size: var(--text-sm);
	}
	dd.mono {
		font-family: var(--font-mono);
	}
	.avatar-fila {
		display: flex;
		align-items: center;
		gap: var(--space-4);
	}
	.avatar {
		width: 4rem;
		height: 4rem;
		border-radius: 50%;
		object-fit: cover;
		border: 1px solid var(--border-color);
		flex: 0 0 auto;
	}
	.avatar-vacio {
		display: flex;
		align-items: center;
		justify-content: center;
		background: var(--bg-overlay);
		color: var(--text-muted);
		font-size: var(--text-xl);
		font-weight: 600;
	}
	.avatar-acciones {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
	}
	.botones {
		display: flex;
		gap: var(--space-2);
	}
	input[type='file'] {
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
		font-size: var(--text-sm);
	}
	.fortaleza {
		margin: calc(-1 * var(--space-2)) 0 var(--space-4) 0;
		font-size: var(--text-xs);
	}
	.fortaleza-0,
	.fortaleza-1 {
		color: var(--danger);
	}
	.fortaleza-2 {
		color: var(--warning);
	}
	.fortaleza-3,
	.fortaleza-4 {
		color: var(--success);
	}
	.token {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		font-size: var(--text-base);
		color: var(--text-primary);
		margin: 0 0 var(--space-4) 0;
	}
	.punto-token {
		display: inline-block;
		width: 1rem;
		height: 1rem;
		border-radius: 50%;
		border: 1px solid var(--border-color);
	}
</style>
