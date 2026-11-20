## 🖥️ App de escritorio y extensión de navegador — uso personal

Son los archivos de esta Release. Un gestor de contraseñas para **una persona**: todo queda cifrado en tu PC y funciona sin servidor, sin Docker y sin cuenta en la nube.

| Archivo | Qué es |
| --- | --- |
| `Ellkan_{{VERSION}}_x64_es-ES.msi` | Windows, instalador (trae la extensión incluida) |
| `Ellkan_{{VERSION}}_x64_portable.zip` | Windows, sin instalar |
| `Ellkan_{{VERSION}}_amd64.AppImage` · `Ellkan_{{VERSION}}_amd64.deb` | Linux (experimental) |
| `ellkan-chrome-{{VERSION}}.zip` (y `-edge`, `-brave`, `-opera`) · `ellkan-firefox-{{VERSION}}.xpi` | Extensión, para cargarla a mano en el navegador |

## 🏢 Servidor para equipos y empresas — imagen Docker (no viene en estos archivos)

El servidor Ellkan con su app web: muchos usuarios, grupos, compartir, SSO/LDAP/SCIM y auditoría. Se instala con Docker, **no con los archivos de arriba, y no incluye la app de escritorio**:

```bash
docker pull ghcr.io/{{DUENO}}/ellkan:{{IMAGEN}}
```

Instalación completa: [README → Instalación rápida](https://github.com/{{REPO}}#instalación-rápida). Al servidor se entra desde el navegador; también se conectan la extensión y, si querés, la app de escritorio. `ellkan-cli_{{VERSION}}_windows_x64.exe` / `ellkan-cli_{{VERSION}}_linux_x64` es la CLI para administrarlo (crear el primer admin, backups).

Para verificar las descargas: `SHA256SUMS.txt`.

---

**EN:** the files in this Release are the desktop app and the browser extension (personal use, no server needed). The team/enterprise server is the Docker image above; it does not include the desktop app. See the [README](https://github.com/{{REPO}}/blob/main/README.en.md#downloads).
