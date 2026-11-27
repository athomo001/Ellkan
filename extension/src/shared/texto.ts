// Autor: Athan Espinoza

/**
 * Quita todas las repeticiones de `caracter` al final de `texto`.
 *
 * Reemplaza a `texto.replace(/\/+$/, '')`: en V8 esa regex es cuadrática
 * cuando hay muchas barras seguidas que no están al final (prueba la
 * secuencia desde cada posición), y la extensión la aplicaba al `pathname` de
 * la página visitada, que controla el sitio (ReDoS, Sonar S8786). Un recorrido
 * desde el final es lineal.
 */
export function quitarFinales(texto: string, caracter: string): string {
	let fin = texto.length;
	while (fin > 0 && texto[fin - 1] === caracter) fin--;
	return fin === texto.length ? texto : texto.slice(0, fin);
}
