// Autor: Athan Espinoza

// Compatibilidad. Toda la lógica de empaquetado (y las banderas nuevas: -b,
// --version minor/major/x.y.z, --no-crx, --out, --dry-run, --check) vive ahora
// en `cli.mjs`. `pnpm run package` sin banderas —y `node package.mjs`— siguen
// dando el mismo resultado de siempre: los 6 artefactos con bump de patch.
// `pnpm run package -- <banderas>` también funciona (pasa argv a `cli.mjs`).
// Ver `extension/README.md`.

import './cli.mjs';
