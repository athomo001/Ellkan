<!-- Autor: Athan Espinoza -->
<script lang="ts">
	let {
		label,
		type = 'text',
		value = $bindable(''),
		error,
		hint,
		autocomplete,
		required = false,
		disabled = false,
		id = `field-${Math.random().toString(36).slice(2)}`
	}: {
		label: string;
		type?: 'text' | 'email' | 'password' | 'number';
		value?: string;
		error?: string;
		hint?: string;
		autocomplete?: string;
		required?: boolean;
		disabled?: boolean;
		id?: string;
	} = $props();
</script>

<div class="field">
	<label for={id}>{label}{#if required}<span class="req" aria-hidden="true"> *</span>{/if}</label>
	<input
		{id}
		{type}
		bind:value
		{disabled}
		{required}
		autocomplete={autocomplete as any}
		aria-invalid={!!error}
		aria-describedby={error ? `${id}-error` : hint ? `${id}-hint` : undefined}
		class:invalid={!!error}
	/>
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
	input {
		background: var(--bg-overlay);
		border: 1px solid var(--border-color);
		border-radius: var(--radius-sm);
		padding: var(--space-2) var(--space-3);
	}
	input:focus-visible {
		border-color: var(--accent-primary);
	}
	input.invalid {
		border-color: var(--danger);
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
