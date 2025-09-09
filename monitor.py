import time
import docker
import os


CHECK_INTERVAL = 20  # segundos


def clear_console():
    os.system("cls" if os.name == "nt" else "clear")


def is_image_up_to_date(client, container, image_name):
    try:
        latest_image = client.images.pull(image_name)
        latest_hash = latest_image.id
        current_hash = container.image.id
        return current_hash == latest_hash, current_hash, latest_hash
    except Exception as e:
        print(f"Error al verificar actualizaciones para {image_name}: {e}")
        return None, None, None


def extract_ports(container):
    ports = {}
    port_bindings = container.attrs["HostConfig"].get("PortBindings", {})
    for container_port, bindings in port_bindings.items():
        host_port = bindings[0].get("HostPort")
        if host_port:
            ports[container_port] = int(host_port)
    return ports


def extract_volumes(container):
    volumes = {}
    for mount in container.attrs.get("Mounts", []):
        source = mount.get("Source")
        target = mount.get("Destination")
        mode = mount.get("Mode", "rw")
        if source and target:
            volumes[source] = {"bind": target, "mode": mode}
    return volumes


def check_and_update_containers(client):
    print("Contenedores en ejecución:")
    containers = client.containers.list()
    if not containers:
        print("No hay contenedores en ejecución.")
        return

    for container in containers:
        if container.name == "monitor":
            continue
        image_name = container.image.tags[0] if container.image.tags else None
        if not image_name:
            print(f"El contenedor {container.name} no tiene una imagen etiquetada.")
        else:
            print(f"- {container.name}: {image_name} [IMAGEN]")

    print()
    for container in containers:
        if container.name == "monitor":
            continue

        image_name = container.image.tags[0] if container.image.tags else None
        if not image_name:
            print(f"El contenedor {container.name} no tiene una imagen etiquetada.")
            continue

        print(f"Verificando la imagen del contenedor {container.name}: {image_name}")
        up_to_date, current_hash, latest_hash = is_image_up_to_date(
            client, container, image_name
        )

        if up_to_date is None:
            print(f"No se pudo verificar la imagen del contenedor {container.name}.")
        elif up_to_date:
            print(
                f"La imagen del contenedor {container.name} ({image_name}) está al día."
            )
        else:
            print(
                f"La imagen del contenedor {container.name} ({image_name}) NO está al día."
            )
            try:
                print(f"Actualizando y reiniciando el contenedor {container.name}...")

                # Extraer configuración
                ports = extract_ports(container)
                volumes = extract_volumes(container)
                environment = container.attrs["Config"].get("Env", [])

                # Detener y eliminar
                container.stop()
                container.remove()

                # Recrear contenedor actualizado
                client.containers.run(
                    image_name,
                    detach=True,
                    name=container.name,
                    ports=ports,
                    volumes=volumes,
                    environment=environment,
                    restart_policy={"Name": "always"},
                )
                print(
                    f"Contenedor {container.name} reiniciado con la imagen actualizada."
                )

                # Eliminar imagen vieja
                print(f"Eliminando la imagen antigua: {current_hash}")
                client.images.remove(current_hash, force=True)
            except Exception as e:
                print(f"Error al actualizar el contenedor {container.name}: {e}")

import time
import docker
import os
from typing import Dict, Any, Tuple, Optional, List

CHECK_INTERVAL = 20  # segundos
SKIP_CONTAINERS = {"monitor"}  # contenedores a ignorar por nombre


def clear_console():
    os.system("cls" if os.name == "nt" else "clear")


def pull_latest(client: docker.DockerClient, image_name: str):
    # Devuelve la imagen recién descargada (o existente si ya está al día)
    return client.images.pull(image_name)


def image_ids_equal(a, b) -> bool:
    return (a or "").split(":")[-1] == (b or "").split(":")[-1]


def is_image_up_to_date(client, container, image_name) -> Tuple[Optional[bool], Optional[str], Optional[str]]:
    try:
        latest_image = pull_latest(client, image_name)
        latest_hash = latest_image.id
        current_hash = container.image.id
        return image_ids_equal(current_hash, latest_hash), current_hash, latest_hash
    except Exception as e:
        print(f"[WARN] No se pudo verificar {image_name}: {e}")
        return None, None, None


def extract_ports(container) -> Dict[str, Any]:
    """
    Devuelve mapeo para docker-py: { "8000/tcp": 8000 } o { "8000/tcp": "127.0.0.1:8000" }
    Solo aplicable cuando NO se usa network_mode=host.
    """
    ports = {}
    pbind = container.attrs["HostConfig"].get("PortBindings") or {}
    for cport, binds in pbind.items():
        if not binds:
            continue
        host_ip = (binds[0].get("HostIp") or "").strip()
        host_port = (binds[0].get("HostPort") or "").strip()
        if not host_port:
            continue
        ports[cport] = int(host_port) if not host_ip else f"{host_ip}:{host_port}"
    return ports


def extract_volumes(container) -> Dict[str, Dict[str, str]]:
    """
    Devuelve { host_path: {"bind": container_path, "mode": "rw"} }
    """
    volumes = {}
    for mount in container.attrs.get("Mounts", []):
        source = mount.get("Source")
        target = mount.get("Destination")
        mode = mount.get("Mode", "rw")
        if source and target:
            volumes[source] = {"bind": target, "mode": mode}
    return volumes


def extract_networking(container) -> Tuple[str, Dict[str, Any]]:
    """
    network_mode: 'default' | 'host' | <nombre de red>
    networks: dict con info por red (para reconectar y restaurar aliases)
    """
    network_mode = container.attrs["HostConfig"].get("NetworkMode") or "default"
    networks = container.attrs["NetworkSettings"].get("Networks") or {}
    return network_mode, networks


def extract_full_config(container) -> Dict[str, Any]:
    cfg = container.attrs["Config"] or {}
    host = container.attrs["HostConfig"] or {}

    # Core
    environment = cfg.get("Env", []) or []
    labels = cfg.get("Labels") or {}
    user = cfg.get("User") or None
    workdir = cfg.get("WorkingDir") or None
    entrypoint = cfg.get("Entrypoint")
    cmd = cfg.get("Cmd")
    stop_timeout = container.attrs.get("StopTimeout") or host.get("StopTimeout")
    healthcheck = cfg.get("Healthcheck")

    # Logging
    log_config = host.get("LogConfig") or {}
    # Reinicio
    restart_policy = host.get("RestartPolicy") or {"Name": "always"}

    # Seguridad / runtime
    cap_add = host.get("CapAdd")
    cap_drop = host.get("CapDrop")
    security_opt = host.get("SecurityOpt")
    privileged = host.get("Privileged")
    devices = host.get("Devices")
    sysctls = host.get("Sysctls")
    ulimits = host.get("Ulimits")
    ipc_mode = host.get("IpcMode")
    pid_mode = host.get("PidMode")
    dns = host.get("Dns")
    dns_search = host.get("DnsSearch")
    extra_hosts = host.get("ExtraHosts")

    # Red
    network_mode, networks = extract_networking(container)
    ports = extract_ports(container) if network_mode != "host" else {}
    volumes = extract_volumes(container)

    return {
        "environment": environment,
        "labels": labels,
        "user": user,
        "workdir": workdir,
        "entrypoint": entrypoint,
        "command": cmd,
        "stop_timeout": stop_timeout,
        "healthcheck": healthcheck,
        "log_config": log_config,
        "restart_policy": restart_policy,
        "cap_add": cap_add,
        "cap_drop": cap_drop,
        "security_opt": security_opt,
        "privileged": privileged,
        "devices": devices,
        "sysctls": sysctls,
        "ulimits": ulimits,
        "ipc_mode": ipc_mode,
        "pid_mode": pid_mode,
        "dns": dns,
        "dns_search": dns_search,
        "extra_hosts": extra_hosts,
        "network_mode": network_mode,
        "networks": networks,
        "ports": ports,
        "volumes": volumes,
    }


def build_run_kwargs(container_name: str, image_name: str, conf: Dict[str, Any]) -> Tuple[Dict[str, Any], List[Tuple[str, List[str]]]]:
    """
    Prepara kwargs para client.containers.run() y una lista de redes extra para conectar luego:
      returns (kwargs, extra_networks)
      extra_networks: lista de (network_name, aliases)
    """
    kwargs: Dict[str, Any] = dict(
        detach=True,
        name=container_name,
        environment=conf["environment"],
        volumes=conf["volumes"],
        labels=conf["labels"],
        restart_policy=conf["restart_policy"] or {"Name": "always"},
    )

    # Opcionales
    if conf["log_config"]:
        kwargs["log_config"] = conf["log_config"]
    if conf["user"]:
        kwargs["user"] = conf["user"]
    if conf["workdir"]:
        kwargs["working_dir"] = conf["workdir"]
    if conf["entrypoint"]:
        kwargs["entrypoint"] = conf["entrypoint"]
    if conf["command"]:
        kwargs["command"] = conf["command"]
    if conf["healthcheck"]:
        kwargs["healthcheck"] = conf["healthcheck"]
    if conf["cap_add"]:
        kwargs["cap_add"] = conf["cap_add"]
    if conf["cap_drop"]:
        kwargs["cap_drop"] = conf["cap_drop"]
    if conf["security_opt"]:
        kwargs["security_opt"] = conf["security_opt"]
    if conf["privileged"] is not None:
        kwargs["privileged"] = conf["privileged"]
    if conf["devices"]:
        kwargs["devices"] = conf["devices"]
    if conf["sysctls"]:
        kwargs["sysctls"] = conf["sysctls"]
    if conf["ulimits"]:
        kwargs["ulimits"] = conf["ulimits"]
    if conf["ipc_mode"]:
        kwargs["ipc_mode"] = conf["ipc_mode"]
    if conf["pid_mode"]:
        kwargs["pid_mode"] = conf["pid_mode"]
    if conf["dns"]:
        kwargs["dns"] = conf["dns"]
    if conf["dns_search"]:
        kwargs["dns_search"] = conf["dns_search"]
    if conf["extra_hosts"]:
        kwargs["extra_hosts"] = conf["extra_hosts"]

    extra_networks: List[Tuple[str, List[str]]] = []

    net_mode = conf["network_mode"]
    nets = conf["networks"] or {}

    if net_mode == "host":
        # Caso clave para tu IP real: preserva host networking
        kwargs["network_mode"] = "host"
    else:
        # Si hay redes definidas, toma la primera como red principal
        default_net = next(iter(nets.keys()), None)
        if default_net:
            kwargs["network"] = default_net
        # Puertos solo si NO es host networking
        if conf["ports"]:
            kwargs["ports"] = conf["ports"]
        # Resto de redes (con aliases) para conectar luego
        for net_name, cfg in nets.items():
            if net_name == kwargs.get("network"):
                continue
            aliases = cfg.get("Aliases") or []
            extra_networks.append((net_name, aliases))

    return kwargs, extra_networks


def recreate_container(client, old_container, image_name: str, conf: Dict[str, Any], current_hash: str):
    name = old_container.name
    print(f"[INFO] Actualizando {name} con {image_name} ...")

    kwargs, extra_nets = build_run_kwargs(name, image_name, conf)

    try:
        # Stop + remove
        stop_timeout = conf["stop_timeout"] or 10
        old_container.stop(timeout=stop_timeout)
        old_container.remove()
    except Exception as e:
        print(f"[WARN] No se pudo detener/eliminar {name}: {e}")

    # Run
    newc = client.containers.run(image_name, **kwargs)
    print(f"[OK] {name} re-creado.")

    # Conectar redes extra (si aplica)
    for net_name, aliases in extra_nets:
        try:
            net = client.networks.get(net_name)
            net.connect(newc, aliases=aliases if aliases else None)
        except Exception as e:
            print(f"[WARN] No pude conectar {name} a red {net_name}: {e}")

    # Limpiar imagen vieja
    try:
        if current_hash:
            print(f"[INFO] Eliminando imagen antigua: {current_hash}")
            client.images.remove(current_hash, force=True)
    except Exception as e:
        print(f"[WARN] No pude eliminar imagen vieja {current_hash}: {e}")


def check_and_update_containers(client):
    print("Contenedores en ejecución:")
    containers = client.containers.list()
    if not containers:
        print("  (ninguno)")
        return

    for c in containers:
        if c.name in SKIP_CONTAINERS:
            continue
        image_name = c.image.tags[0] if c.image.tags else None
        print(f"- {c.name}: {image_name or '<sin tag>'}")

    print()
    for container in containers:
        if container.name in SKIP_CONTAINERS:
            continue

        image_name = container.image.tags[0] if container.image.tags else None
        if not image_name:
            print(f"[SKIP] {container.name} no tiene imagen etiquetada.")
            continue

        print(f"[CHECK] {container.name} → {image_name}")
        up_to_date, current_hash, latest_hash = is_image_up_to_date(client, container, image_name)

        if up_to_date is None:
            print(f"[WARN] No se pudo verificar {image_name}.")
            continue

        if up_to_date:
            print(f"[OK] {image_name} está al día.")
            continue

        print(f"[UPDATE] {image_name} NO está al día. Re-creando…")
        try:
            conf = extract_full_config(container)
            recreate_container(client, container, image_name, conf, current_hash)
        except Exception as e:
            print(f"[ERROR] Falló actualización de {container.name}: {e}")


def monitor_containers():
    client = docker.from_env()
    while True:
        clear_console()
        try:
            check_and_update_containers(client)
        except Exception as e:
            print(f"[ERROR] Ciclo de verificación: {e}")
        print(f"\nEsperando {CHECK_INTERVAL} segundos para la próxima comprobación...")
        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    try:
        monitor_containers()
    except KeyboardInterrupt:
        print("\nMonitoreo detenido por el usuario.")

def monitor_containers():
    client = docker.from_env()
    while True:
        clear_console()
        check_and_update_containers(client)
        print()
        print(f"Esperando {CHECK_INTERVAL} segundos para la próxima comprobación...")
        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    try:
        monitor_containers()
    except KeyboardInterrupt:
        print("\nMonitoreo detenido por el usuario.")
