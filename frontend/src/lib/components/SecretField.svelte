<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// F-39: oculto por defecto, revelar con clic explícito — nunca se pinta
	// en claro sólo por abrir el recurso. Copiar dispara la limpieza
	// automática configurable (`preferencias.clipboardClearMinutes`).
	import { copiarConLimpieza } from '$lib/clipboard';
	import { preferencias } from '$lib/state/session';
	import { t } from '$lib/i18n';

	let { label, valor }: { label: string; valor: string } = $props();

	let revelado = $state(false);
	let copiado = $state(false);

	async function copiar() {
		await copiarConLimpieza(valor, $preferencias.clipboardClearMinutes);
		copiado = true;
		setTimeout(() => (copiado = false), 2000);
	}
</script>

<div class="field">
	<span class="label">{label}</span>
	<div class="fila">
		<code class="valor">{revelado ? valor : '••••••••••••'}</code>
		<button
			type="button"
			class="icono"
			onclick={() => (revelado = !revelado)}
			aria-label={revelado ? $t.secretField.ocultar : $t.secretField.revelar}
		>
			{revelado ? '🙈' : '👁'}
		</button>
		<button type="button" class="icono" onclick={copiar} aria-label={$t.secretField.copiar}>
			{copiado ? '✓' : '⧉'}
		</button>
	</div>
</div>

<style>
	.field {
		display: flex;
		flex-direction: column;
		gap: var(--space-1);
		margin-bottom: var(--space-3);
	}
	.label {
		font-size: var(--text-sm);
		color: var(--text-secondary);
		font-weight: 500;
	}
	.fila {
		display: flex;
		align-items: center;
		gap: var(--space-2);
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
	}
	.valor {
		flex: 1;
		font-family: var(--font-mono);
		color: var(--text-primary);
		overflow: hidden;
		text-overflow: ellipsis;
		white-space: nowrap;
	}
	.icono {
		background: none;
		border: none;
		cursor: pointer;
		font-size: var(--text-base);
		line-height: 1;
		padding: var(--space-1);
		color: var(--text-secondary);
	}
	.icono:hover {
		color: var(--text-primary);
	}
</style>
