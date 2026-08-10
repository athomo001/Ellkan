<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-01: "Avatar" — sección de "Mi cuenta" ((app)/settings/+layout.svelte).
	import { onMount } from 'svelte';
	import Card from '$lib/components/Card.svelte';
	import Button from '$lib/components/Button.svelte';
	import { perfilApi, avatarApi, obtenerAvatarUrl, type Perfil } from '$lib/api/profile';
	import { bytesABase64 } from '$lib/crypto/b64';
	import { t } from '$lib/i18n';
	import { ApiError } from '$lib/api/client';

	let perfil = $state<Perfil | undefined>();
	let avatarUrl = $state<string | null>(null);
	let archivoAvatar = $state<File | undefined>();
	let subiendo = $state(false);
	let error = $state<string | undefined>();

	async function cargarAvatar() {
		try {
			avatarUrl = await obtenerAvatarUrl();
		} catch {
			/* sin avatar visible si esto falla, el resto de la página sigue */
		}
	}

	onMount(async () => {
		cargarAvatar();
		perfilApi.obtener().then((p) => (perfil = p)).catch(() => {});
	});

	function alElegirAvatar(e: Event) {
		archivoAvatar = (e.target as HTMLInputElement).files?.[0];
		error = undefined;
	}

	async function subirAvatar() {
		if (!archivoAvatar) return;
		error = undefined;
		subiendo = true;
		try {
			const bytes = new Uint8Array(await archivoAvatar.arrayBuffer());
			await avatarApi.actualizar(bytesABase64(bytes), archivoAvatar.type);
			archivoAvatar = undefined;
			await cargarAvatar();
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.settingsProfile.avatarErrorSubir;
		} finally {
			subiendo = false;
		}
	}

	async function quitarAvatar() {
		error = undefined;
		subiendo = true;
		try {
			await avatarApi.eliminar();
			avatarUrl = null;
		} catch (err) {
			error = err instanceof ApiError ? err.message : $t.settingsProfile.avatarErrorQuitar;
		} finally {
			subiendo = false;
		}
	}
</script>

<svelte:head>
	<title>{$t.settingsProfile.avatarTitulo} — Ellkan</title>
</svelte:head>

<h1>{$t.settingsProfile.avatarTitulo}</h1>
<Card>
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
				<Button variant="secondary" onclick={subirAvatar} disabled={!archivoAvatar} loading={subiendo}>
					{$t.settingsProfile.avatarSubir}
				</Button>
				{#if avatarUrl}
					<Button variant="danger" onclick={quitarAvatar} loading={subiendo}>
						{$t.settingsProfile.avatarQuitar}
					</Button>
				{/if}
			</div>
		</div>
	</div>
	{#if error}<p class="error">{error}</p>{/if}
</Card>

<style>
	h1 {
		margin: 0 0 var(--space-6) 0;
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
</style>
