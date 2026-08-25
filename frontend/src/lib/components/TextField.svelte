<!-- Autor: Athan Espinoza -->
<script lang="ts">
	// 2026-08-13, hallazgo real de uso: ningún campo `password` tenía forma
	// de revelar lo tipeado (a diferencia de `SecretField`, que sí lo hace
	// para un secreto ya recuperado) — un typo quedaba invisible hasta que
	// el submit fallaba. Mismo ícono/criterio que `SecretField` (👁/🙈),
	// puesto acá una sola vez porque `TextField` es el campo compartido por
	// login/registro/cambio de passphrase/etc.
	import { t } from '$lib/i18n';

	let {
		label,
		type = 'text',
		value = $bindable(''),
		error,
		hint,
		autocomplete,
		required = false,
		disabled = false,
		placeholder,
		oninput,
		id = `field-${Math.random().toString(36).slice(2)}`
	}: {
		label: string;
		type?: 'text' | 'email' | 'password' | 'number' | 'date';
		value?: string;
		error?: string;
		hint?: string;
		autocomplete?: string;
		required?: boolean;
		disabled?: boolean;
		placeholder?: string;
		oninput?: (e: Event & { currentTarget: HTMLInputElement }) => void;
		id?: string;
	} = $props();

	let mostrar = $state(false);
	const tipoEfectivo = $derived(type === 'password' && mostrar ? 'text' : type);
</script>

<div class="field">
	{#if label}<label for={id}>{label}{#if required}<span class="req" aria-hidden="true"> *</span>{/if}</label>{/if}
	<div class="fila-input" class:con-toggle={type === 'password'}>
		<input
			{id}
			type={tipoEfectivo}
			bind:value
			{disabled}
			{required}
			{placeholder}
			{oninput}
			autocomplete={autocomplete as any}
			aria-invalid={!!error}
			aria-describedby={error ? `${id}-error` : hint ? `${id}-hint` : undefined}
			class:invalid={!!error}
		/>
		{#if type === 'password'}
			<button
				type="button"
				class="toggle-ver"
				onclick={() => (mostrar = !mostrar)}
				aria-label={mostrar ? $t.secretField.ocultar : $t.secretField.revelar}
				tabindex="-1"
			>
				{mostrar ? '🙈' : '👁'}
			</button>
		{/if}
	</div>
	{#if error}
		<p id="{id}-error" class="msg error">{error}</p>
	{:else if hint}
		<p id="{id}-hint" class="msg hint">{hint}</p>
	{/if}
</div>

<style>
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
	.req {
		color: var(--danger);
	}
	.fila-input {
		position: relative;
		display: flex;
	}
	input {
		width: 100%;
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
		font-size: var(--text-sm);
		transition:
			border-color 0.12s ease,
			box-shadow 0.12s ease;
	}
	.fila-input.con-toggle input {
		padding-right: var(--space-8);
	}
	input:focus-visible {
		outline: none;
		border-color: var(--accent-primary);
		box-shadow: 0 0 0 3px color-mix(in srgb, var(--accent-primary) 25%, transparent);
	}
	input.invalid {
		border-color: var(--danger);
	}
	.toggle-ver {
		position: absolute;
		right: var(--space-1);
		top: 50%;
		transform: translateY(-50%);
		background: none;
		border: none;
		padding: var(--space-1) var(--space-2);
		font-size: var(--text-sm);
		line-height: 1;
		cursor: pointer;
	}
	.msg {
		margin: 0;
		font-size: var(--text-xs);
	}
	.msg.error {
		color: var(--danger);
	}
	.msg.hint {
		color: var(--text-muted);
	}
</style>
