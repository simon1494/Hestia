# Hestia

Actualizador de contenedores Docker independientes, con comprobación de salud y
recuperación del contenedor anterior. Compatible con Docker Hub y GHCR mediante
las credenciales de Docker del usuario que ejecuta el servicio.

## Qué cambia respecto del monitor anterior

- Solo actualiza los contenedores enumerados en `hestia.json`; no recorre todos
  los servicios del servidor. Es necesario crear esa configuración al migrar.
- Sigue la referencia `image` configurada o, si se omite, `Config.Image` del
  contenedor. No elige una etiqueta arbitraria de la imagen descargada.
- Descarga antes de detener el servicio y crea el reemplazo con el ID exacto
  descargado. Conserva puertos e IP de escucha, política de reinicio, límites,
  opciones de seguridad, variables personalizadas y volúmenes existentes.
- Los valores heredados de la imagen (comando, entrypoint, healthcheck, variables,
  usuario, etc.) siguen los valores de la nueva imagen. Docker no permite distinguir
  una opción explícita que coincide exactamente con el valor heredado: en ese caso
  Hestia la considera heredada.
- Exige que el contenedor actual esté saludable y que el reemplazo tenga un
  `HEALTHCHECK`. Conserva el original hasta que el nuevo esté saludable.
- Si la creación, el arranque o la salud fallan, recupera el contenedor original.
  El ID de la imagen fallida queda registrado para no interrumpir el sitio cada
  minuto intentando instalarla otra vez. Una imagen diferente se prueba normalmente.
- Guarda un registro de la operación en `.hestia/`; si el proceso se interrumpe,
  recupera la operación pendiente antes de iniciar otra. No borres ese directorio.
- No elimina imágenes anteriores ni volúmenes. Registra actividad en stdout/journal.

## Configuración para Zeta Ka

Copiar `hestia.example.json` como `hestia.json`:

```json
{
  "interval": 60,
  "health_timeout": 120,
  "stop_timeout": 20,
  "containers": [
    {
      "name": "zeta-ka-prueba",
      "image": "ghcr.io/simon1494/zeta-ka:latest"
    }
  ]
}
```

Los tiempos se expresan en segundos. `name` es el nombre del contenedor en Docker,
no el dominio público. Aunque el sitio ahora sea `www.zeta-ka.studio`, el contenedor
que se creó en el servidor se llama `zeta-ka-prueba` y publica
`127.0.0.1:8081:8080`. Hestia conserva ese puerto; Nginx y Cloudflare no necesitan cambios.

La referencia explícita a `:latest` permite seguirla aunque el contenedor actual
se haya creado con `:0.1.0`. Si ambas referencias apuntan a la misma imagen,
no se reinicia nada. Al aparecer una imagen nueva, el contenedor se recrea.
No hace falta reemplazarlo manualmente para cambiar de etiqueta.

El workflow de Zeta Ka publica imágenes al crear tags `v*`, por ejemplo `v0.1.1`;
actualiza la etiqueta de esa versión y `latest`. Un commit sin tag no publica imagen.
Publicar `latest` con este monitor activo implica desplegar esa imagen.

## Instalación en el servidor

Los comandos suponen usuario `server2`, repositorio en `/home/server2/Hestia`,
Docker funcionando sin `sudo` y acceso de lectura a la imagen en GHCR.
Primero deben estar publicados los cambios de este repositorio; un `git clone`
no trae modificaciones que todavía estén solamente en el workspace local.

```bash
sudo apt-get update
sudo apt-get install -y git python3-venv

# Si todavía no existe la copia en el servidor:
git clone https://github.com/simon1494/Hestia.git /home/server2/Hestia
cd /home/server2/Hestia

# Si ya existía, entrar a esa carpeta y actualizarla con git pull --ff-only.
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
cp -n hestia.example.json hestia.json
```

### Credenciales de GHCR y Docker Snap

El SDK usa la configuración de Docker del usuario del servicio, no las credenciales
de `root`. En instalaciones Snap, el login puede estar en
`~/snap/docker/current/.docker` en lugar de `~/.docker`.
Seleccioná el directorio existente sin copiar ni mostrar el token:

```bash
cd /home/server2/Hestia
if [ -z "${DOCKER_CONFIG:-}" ]; then
  if [ -f "$HOME/snap/docker/current/.docker/config.json" ]; then
    export DOCKER_CONFIG="$HOME/snap/docker/current/.docker"
  else
    export DOCKER_CONFIG="$HOME/.docker"
  fi
fi
printf 'DOCKER_CONFIG=%s\n' "$DOCKER_CONFIG" > .env
chmod 600 .env

.venv/bin/python monitor.py --once --dry-run
```

`--dry-run` descarga y valida la imagen disponible, pero no detiene ni reemplaza
contenedores. Si la imagen es privada y aparece `unauthorized`, verificá que ese
directorio corresponda al login de `server2` en GHCR. Si hace falta renovar el login,
usá `docker login ghcr.io -u simon1494` en la terminal del servidor con el token
`read:packages` como contraseña. No guardes tokens en este repositorio.

Para aplicar una única comprobación/actualización y luego activar el servicio:

```bash
.venv/bin/python monitor.py --once
curl -fsS http://127.0.0.1:8081/healthz

sudo install -m 644 service.template /etc/systemd/system/hestia.service
sudo systemctl daemon-reload
sudo systemctl enable --now hestia.service
sudo systemctl status hestia.service --no-pager
```

Si ya existía una versión del servicio, detenela antes de ejecutar el nuevo monitor
y sustituir su unidad. Adaptá las rutas de `service.template` si usás otra carpeta.
El servicio no depende de una unidad `docker.service`, por lo que también funciona
con Docker instalado mediante Snap. Si Docker aún no está disponible al arrancar,
systemd reintenta ejecutar Hestia.

## Operación y recuperación

```bash
# Ver actividad y errores:
journalctl -u hestia.service -f

# Pausar actualizaciones (la web sigue funcionando):
sudo systemctl stop hestia.service

# Reintentar expresamente una imagen que falló, sin otro monitor activo:
cd /home/server2/Hestia
set -a
. ./.env
set +a
.venv/bin/python monitor.py --once --retry-failed
sudo systemctl start hestia.service
```

Un bloqueo de archivo impide dos monitores con el mismo `--state-dir`. Todas las
instancias que administren los mismos contenedores deben compartir ese directorio.
No ejecutes otro actualizador sobre los mismos contenedores.

La sustitución implica una interrupción breve mientras se detiene y arranca el
servicio. No es un despliegue sin cortes. Si se interrumpe una operación, Hestia
prioriza recuperar el contenedor anterior al volver a iniciarse. Si Docker no está
disponible o la recuperación falla, conserva el registro y deja el error en el journal
para reintentar al reiniciar; no continúa reemplazando otros contenedores.

La recuperación restaura el contenedor, no revierte cambios que la aplicación haya
hecho en datos de volúmenes. Está pensado inicialmente para aplicaciones como esta
web estática. Los contenedores de Compose/Swarm, redes personalizadas o compartidas,
`--rm`, enlaces y dependencias `volumes-from` se rechazan antes de detener nada;
deben desplegarse mediante su orquestador. Se admiten redes `bridge`, `host` y `none`.

## Pruebas

```bash
python -m unittest test_monitor -v
```

Las pruebas de integración requieren Docker y la imagen local de Zeta Ka
`zeta-ka:local`. Crean recursos temporales con un prefijo único, verifican una
actualización correcta, una imagen insalubre, un fallo de arranque y una interrupción
del proceso; después limpian exclusivamente esos recursos. No consultan GHCR ni
actualizan la web existente.

```bash
HESTIA_DOCKER_TESTS=1 python -m unittest test_docker_integration -v
```

En PowerShell:

```powershell
$env:HESTIA_DOCKER_TESTS = '1'
python -m unittest test_docker_integration -v
```

Referencias: [autenticación del SDK](https://docs.docker.com/reference/api/engine/sdk/examples/),
[Docker SDK](https://docker-py.readthedocs.io/en/stable/api.html),
[políticas de reinicio](https://docs.docker.com/engine/containers/start-containers-automatically/).
