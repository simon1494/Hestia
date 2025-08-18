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
