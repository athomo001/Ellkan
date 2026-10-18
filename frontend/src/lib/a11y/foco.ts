// Autor: Athan Espinoza

// spec/14 punto 6.12 (WCAG 2.2: 2.1.2, 2.4.3, 2.4.7): foco en diálogos
// modales. Al abrirse, el foco entra al diálogo (al primer campo, o al
// elemento con `data-autofocus`); Tab y Shift+Tab quedan atrapados adentro
// (antes se podía salir y terminar tabulando por la página de atrás, tapada);
// al cerrarse, el foco vuelve a donde estaba (normalmente, el botón que lo abrió).

const ENFOCABLES = [
	'a[href]',
	'button:not([disabled])',
	'input:not([disabled]):not([type="hidden"])',
	'select:not([disabled])',
	'textarea:not([disabled])',
	'[tabindex]:not([tabindex="-1"])',
	'[contenteditable="true"]'
].join(',');

function enfocables(raiz: HTMLElement): HTMLElement[] {
	return Array.from(raiz.querySelectorAll<HTMLElement>(ENFOCABLES)).filter((el) => el.offsetParent !== null || el === document.activeElement);
}

/** Acción de Svelte: `<div use:atraparFoco>`. */
export function atraparFoco(nodo: HTMLElement) {
	const anterior = document.activeElement instanceof HTMLElement ? document.activeElement : null;

	// Después del render (y de las transiciones de entrada que montan el contenido).
	queueMicrotask(() => {
		const inicial = nodo.querySelector<HTMLElement>('[data-autofocus]') ?? enfocables(nodo)[0] ?? nodo;
		if (inicial === nodo && !nodo.hasAttribute('tabindex')) nodo.setAttribute('tabindex', '-1');
		inicial.focus();
	});

	function alPresionar(e: KeyboardEvent) {
		if (e.key !== 'Tab') return;
		const lista = enfocables(nodo);
		if (lista.length === 0) {
			e.preventDefault();
			nodo.focus();
			return;
		}
		const primero = lista[0];
		const ultimo = lista[lista.length - 1];
		const activo = document.activeElement;
		if (e.shiftKey && (activo === primero || !nodo.contains(activo))) {
			e.preventDefault();
			ultimo.focus();
		} else if (!e.shiftKey && (activo === ultimo || !nodo.contains(activo))) {
			e.preventDefault();
			primero.focus();
		}
	}
	document.addEventListener('keydown', alPresionar, true);

	return {
		destroy() {
			document.removeEventListener('keydown', alPresionar, true);
			// Sólo si el elemento sigue en la página (no, por ejemplo, tras navegar).
			if (anterior && anterior.isConnected) anterior.focus();
		}
	};
}
