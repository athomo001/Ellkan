<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-06: alta y rotación de la clave de metadata compartida. La clave
	// nueva se genera 100% client-side (par X25519) y su privada se sella
	// para el propio admin que la crea.
	//
	// Hallazgo real de uso 2026-08-10: "sumar destinatarios" quedaba
	// pendiente acá mismo ("depende de un selector de usuarios real") pero
	// ese bloqueo ya no existe (F-29, `GET /admin/users`, está desde hace
	// rato) — nunca se volvió a esta página. Consecuencia real: sólo el
	// admin que crea una metadata key tenía acceso de verdad a ella, así que
	// ningún recurso `shared_key` era compartible con nadie más en la
	// práctica. `agregarMiembro` de abajo cierra ese gap — abre la privada
	// de la key con la propia clave, la resella para el destinatario nuevo
	// (mismo patrón que agregar un miembro a un grupo, F-12) y la persiste
	// vía `POST /admin/metadata-keys/{id}/members`, sin rotar la key.
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import TextField from '$lib/components/TextField.svelte';
	import { metadataKeysApi, type MetadataKeyAdmin, type RotationStatus } from '$lib/api/admin';
	import { cargarCrypto } from '$lib/crypto/wasm';
	import { bytesABase64, base64ABytes } from '$lib/crypto/b64';
	import { sesion, clavesDesbloqueadas } from '$lib/state/session';
	import { t } from '$lib/i18n';
	import { ApiError, api } from '$lib/api/client';

	let cargando = $state(true);
	let error = $state<string | undefined>();
	let claves = $state<MetadataKeyAdmin[]>([]);
	let estadoRotacion = $state<RotationStatus | undefined>();
	let creando = $state(false);
	let rotando = $state(false);

	async function cargar() {
		cargando = true;
		error = undefined;
		try {
			claves = await metadataKeysApi.listar();
			estadoRotacion = await metadataKeysApi.estadoRotacion();
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			cargando = false;
		}
	}

	onMount(cargar);

	async function crear() {
		if (!$clavesDesbloqueadas || !$sesion.userId) return;
		error = undefined;
		creando = true;
		try {
			const wasm = await cargarCrypto();
			const identidad = wasm.generar_identidad();
			const id = crypto.randomUUID();
			const fingerprint = bytesABase64(
				new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(identidad.x25519_public)))
			).slice(0, 16);
			const sealedParaMi = wasm.sellar_para($clavesDesbloqueadas.x25519Public, identidad.x25519_private);
			await metadataKeysApi.crear(id, bytesABase64(identidad.x25519_public), fingerprint, [
				{ user_id: $sesion.userId, sealed_private_key_b64: bytesABase64(sealedParaMi) }
			]);
			await cargar();
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			creando = false;
		}
	}

	let agregandoMiembroParaClave = $state<string | undefined>();
	let emailMiembroNuevo = $state('');
	let agregandoMiembro = $state(false);
	let errorMiembro = $state<string | undefined>();

	async function agregarMiembro(clave: MetadataKeyAdmin, e: SubmitEvent) {
		e.preventDefault();
		if (!$clavesDesbloqueadas || !clave.own_sealed_private_key_b64) return;
		errorMiembro = undefined;
		agregandoMiembro = true;
		try {
			const wasm = await cargarCrypto();
			const privadaClave = wasm.abrir_sellado($clavesDesbloqueadas.x25519Private, base64ABytes(clave.own_sealed_private_key_b64));
			const destinatario = await api.get<{ user_id: string; public_key_x25519_b64: string }>(
				`/users/${encodeURIComponent(emailMiembroNuevo)}/public-key`
			);
			const sellado = wasm.sellar_para(base64ABytes(destinatario.public_key_x25519_b64), privadaClave);
			await metadataKeysApi.agregarMiembro(clave.id, destinatario.user_id, bytesABase64(sellado));
			emailMiembroNuevo = '';
			agregandoMiembroParaClave = undefined;
		} catch (err) {
			errorMiembro = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			agregandoMiembro = false;
		}
	}

	async function rotar() {
		if (!$clavesDesbloqueadas || !$sesion.userId) return;
		error = undefined;
		rotando = true;
		try {
			const wasm = await cargarCrypto();
			const identidad = wasm.generar_identidad();
			const id = crypto.randomUUID();
			const fingerprint = bytesABase64(
				new Uint8Array(await crypto.subtle.digest('SHA-256', new Uint8Array(identidad.x25519_public)))
			).slice(0, 16);
			const sealedParaMi = wasm.sellar_para($clavesDesbloqueadas.x25519Public, identidad.x25519_private);
			await metadataKeysApi.rotar(id, bytesABase64(identidad.x25519_public), fingerprint, [
				{ user_id: $sesion.userId, sealed_private_key_b64: bytesABase64(sealedParaMi) }
			]);
			await cargar();
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.admin.comun.error;
		} finally {
			rotando = false;
		}
	}
</script>

<h1>{$t.admin.metadataKeys.titulo}</h1>
<Card>
	{#if cargando}
		<p>{$t.admin.comun.cargando}</p>
	{:else}
		{#if error}<p class="error">{error}</p>{/if}

		<h2>{$t.admin.metadataKeys.activas}</h2>
		<ul class="lista">
			{#each claves as clave (clave.id)}
				<li>
					<span class="fp">{$t.admin.metadataKeys.fingerprint}: {clave.fingerprint}</span>
					<span class="secundario">
						{$t.admin.metadataKeys.expira}: {clave.expired_at ?? $t.admin.metadataKeys.nuncaExpira}
					</span>
					{#if !clave.expired_at && clave.own_sealed_private_key_b64}
						{#if agregandoMiembroParaClave === clave.id}
							<form class="form-miembro" onsubmit={(e) => agregarMiembro(clave, e)}>
								<TextField label={$t.admin.metadataKeys.emailMiembroNuevo} type="email" bind:value={emailMiembroNuevo} required />
								{#if errorMiembro}<p class="error">{errorMiembro}</p>{/if}
								<div class="botones">
									<Button type="submit" variant="primary" loading={agregandoMiembro}>{$t.admin.metadataKeys.agregarMiembro}</Button>
									<Button type="button" variant="ghost" onclick={() => (agregandoMiembroParaClave = undefined)}>
										{$t.admin.comun.cancelar}
									</Button>
								</div>
							</form>
						{:else}
							<button type="button" class="link" onclick={() => (agregandoMiembroParaClave = clave.id)}>
								{$t.admin.metadataKeys.agregarMiembro}
							</button>
						{/if}
					{/if}
				</li>
			{/each}
		</ul>

		<div class="botones">
			<Button variant="primary" onclick={crear} loading={creando}>{$t.admin.metadataKeys.crearNueva}</Button>
			<Button variant="secondary" onclick={rotar} loading={rotando}>{$t.admin.metadataKeys.rotar}</Button>
		</div>

		<h2>{$t.admin.metadataKeys.estadoRotacion}</h2>
		{#if estadoRotacion}
			{#if estadoRotacion.activa}
				<p>{$t.admin.metadataKeys.rotacionActiva}</p>
				<p class="secundario">
					{$t.admin.metadataKeys.pendientes}: {estadoRotacion.pendientes ?? 0} / {estadoRotacion.total_al_iniciar ?? 0}
				</p>
			{:else}
				<p class="secundario">{$t.admin.metadataKeys.sinRotacion}</p>
			{/if}
		{/if}
	{/if}
</Card>

<style>
	h1 {
		margin: 0 0 var(--space-6) 0;
		font-size: var(--text-2xl);
		color: var(--text-primary);
	}
	h2 {
		margin: var(--space-4) 0 var(--space-2) 0;
		font-size: var(--text-lg);
		color: var(--text-primary);
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
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
	}
	.fp {
		font-family: var(--font-mono);
		color: var(--text-primary);
		font-size: var(--text-sm);
	}
	.secundario {
		color: var(--text-muted);
		font-size: var(--text-xs);
	}
	.botones {
		display: flex;
		gap: var(--space-2);
		margin: var(--space-4) 0;
	}
	.error {
		color: var(--danger);
		font-size: var(--text-sm);
	}
	.form-miembro {
		display: flex;
		flex-direction: column;
		gap: var(--space-2);
		margin-top: var(--space-2);
		padding-top: var(--space-2);
		border-top: 1px solid var(--border-color);
	}
	.link {
		background: none;
		border: none;
		padding: 0;
		margin-top: var(--space-2);
		font: inherit;
		font-size: var(--text-sm);
		color: var(--accent-primary);
		cursor: pointer;
		align-self: flex-start;
	}
</style>
