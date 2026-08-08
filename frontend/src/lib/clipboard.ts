// Autor: Athan Espinoza

// F-39: limpieza automática del portapapeles — compara que el portapapeles
// siga teniendo exactamente lo que Ellkan copió antes de borrarlo, para no
// pisar algo distinto que el usuario haya copiado después.

export async function copiarConLimpieza(texto: string, minutos: number): Promise<void> {
	await navigator.clipboard.writeText(texto);
	if (minutos <= 0) return;

	setTimeout(async () => {
		try {
			const actual = await navigator.clipboard.readText();
			if (actual === texto) await navigator.clipboard.writeText('');
		} catch {
			// Permiso de portapapeles denegado, o la pestaña perdió el foco
			// (algunos navegadores exigen foco para `readText`) — no hay nada
			// seguro que hacer acá, no vale la pena romper el flujo por esto.
		}
	}, minutos * 60_000);
}
