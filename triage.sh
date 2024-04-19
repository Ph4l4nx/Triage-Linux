#!/bin/bash
# Ejecutar con sudo para obtener la maxima informacion posible del sistema

if [ "$EUID" -ne 0 ]; then
    echo "Este script necesita ser ejecutado con sudo."
fi

# Instalacion de herramientas en caso de que no esten instaladas en el sistema operativo
apt install net-tools -y >/dev/null 2>&1
apt install nmap -y >/dev/null 2>&1
apt install binutils -y >/dev/null 2>&1
apt install parallel -y >/dev/null 2>&1
apt install curl -y >/dev/null 2>&1

# Nombre del archivo de salida
output_file="triage_$(hostname)_$(cat /etc/machine-id)_$(date +"%Y-%m-%d_%H-%M-%S").txt"

# Función para imprimir en color rojo
print_red() {
    echo -e "\e[91m$@\e[0m"
}
print_yellow() {
    echo -e "\e[93m$@\e[0m"
}

# Información del sistema
print_red "###############################################     " >> "$output_file"
print_red "####                                       ####     " >> "$output_file"
print_red "####      Informacion del sistema          ####     " >> "$output_file"
print_red "####                                       ####     " >> "$output_file"
print_red "###############################################     " >> "$output_file"
echo -e "$(print_yellow 'Usuario actual: ')$(whoami)" >> "$output_file" 
echo -e "$(print_yellow 'Nombre del equipo: ')$(hostname)" >> "$output_file" 
echo -e "$(print_yellow 'Machine ID: ')$(cat /etc/machine-id)" >> "$output_file"
echo -e "$(print_yellow 'Kernel, Sistema Operativo, Hora y Arquitectura: ')$(uname -a)" >> "$output_file"
print_yellow "Informacion de Red:" >> "$output_file" 
ip a | awk '/^[0-9]/ {gsub(/:/,"",$2); print "Nombre de la interfaz:", $2} /inet / {print "Dirección IP:", $2} NR > 1 && /nameserver/ {print ""}' >> "$output_file"
print_yellow "Configuracion de DNS:" >> "$output_file" 
sed '/^\s*#/d; /^$/d' /etc/resolv.conf >> "$output_file" >> "$output_file"
print_yellow "Hora del sistema:" >> "$output_file"
timedatectl >> "$output_file" 2>/dev/null
print_yellow "IP de salida:" >> "$output_file"
{ curl ipinfo.io/ip ; echo -e "\n"; } >> "$output_file" 2>/dev/null
print_yellow "Variables de entorno:" >> "$output_file"
{ env; echo -e "\n\n"; } >> "$output_file" 2>/dev/null

# Conexiones
print_red "###############################################     " >> "$output_file"
print_red "####                                       ####     " >> "$output_file"
print_red "####             Conexiones                ####     " >> "$output_file"
print_red "####                                       ####     " >> "$output_file"
print_red "###############################################     " >> "$output_file"
print_yellow "---- Ultimas conexiones realizadas ----">> "$output_file"
last -Faixw >> "$output_file" 2>/dev/null
print_yellow "---- Registro de autenticacion SSH ----">> "$output_file"
tail -n 10 /var/log/auth.log | grep ssh >> "$output_file" 2>/dev/null
print_yellow "---- Conexiones TCP y UDP entrantes/establecidas----">> "$output_file"
netstat -putona >> "$output_file" 2>/dev/null
print_yellow "---- Conexiones TCP ----" >> "$output_file"
ss -tpn >> "$output_file" 2>/dev/null
print_yellow "---- Sockets de Red ----" >> "$output_file"
lsof -i >> "$output_file" 2>/dev/null
print_yellow "---- Puertos abiertos ----" >> "$output_file"
nmap localhost | grep 'open' >> "$output_file" 2>/dev/null
print_yellow "---- Usuarios conectados al sistema ----" >> "$output_file" 
{ who; echo -e "\n\n"; } >> "$output_file" 2>/dev/null 

# Comandos para procesos actualmente corriendo
print_red "###############################################     " >> "$output_file"
print_red "####                                       ####     " >> "$output_file"
print_red "####             Procesos                  ####     " >> "$output_file"
print_red "####                                       ####     " >> "$output_file"
print_red "###############################################     " >> "$output_file"
print_yellow "---- Procesos de todos los usuarios ----" >> "$output_file"
ps aux >> "$output_file" 2>/dev/null
print_yellow "---- Arbol de procesos ----" >> "$output_file"
pstree >> "$output_file" 2>/dev/null 
print_yellow "---- Procesos de otros terminales ----" >> "$output_file"
ps -auxwf >> "$output_file" 2>/dev/null
print_yellow "---- Recursos del sistema y procesos en ejecucion ----" >> "$output_file"
{ top -n 1 -b; echo -e "\n\n"; } >> "$output_file" 2>/dev/null

# Comandos para listar servicios instalados y corriendo
print_red "###############################################     " >> "$output_file"
print_red "####                                       ####     " >> "$output_file"
print_red "####             Servicios                 ####     " >> "$output_file"
print_red "####                                       ####     " >> "$output_file"
print_red "###############################################     " >> "$output_file"
print_yellow "---- Servicios instalados y corriendo ----" >> "$output_file"
service --status-all >> "$output_file" 2>/dev/null
print_yellow "---- Contexto de los servicios por cada usuario ----" >> "$output_file"
{ systemctl list-units --type=service --state=running --no-legend | awk '{print $1}' | while read -r service; do echo -n "$service: "; ps -p $(systemctl show -p MainPID $service --value) -o user= ; done;echo -e "\n\n"; } >> "$output_file" 2>/dev/null

# Ficheros 
print_red "###############################################     " >> "$output_file"
print_red "####                                       ####     " >> "$output_file"
print_red "####      Ficheros del sistema             ####     " >> "$output_file"
print_red "####                                       ####     " >> "$output_file"
print_red "###############################################     " >> "$output_file"
print_yellow "Fichero Shadow:" >> "$output_file" 
cat /etc/shadow >> "$output_file" 2>/dev/null >> "$output_file"
print_yellow "Fichero Passwd:" >> "$output_file" 
cat /etc/passwd >> "$output_file" 2>/dev/null >> "$output_file"
print_yellow "Grupos de usuarios:" >> "$output_file" 
cat /etc/group >> "$output_file" 2>/dev/null >> "$output_file"
print_yellow "Usuarios que tienen permiso para ejecutar comandos con sudo:" >> "$output_file" 
grep -v '^#' /etc/sudoers | grep -v '^$' >> "$output_file" 2>/dev/null
print_yellow "Hosts o usuarios que tienen permiso para acceder a servicios como SSH o FTP:" >> "$output_file" 
grep -v -E "^\s*#|^\s*$" /etc/hosts.allow >> "$output_file"
print_yellow "Configuracion del servicio SSH:" >> "$output_file" 
{ grep -v -e '^#' -e '^[[:space:]]*$' /etc/ssh/ssh_config; echo -e "\n\n";} >> "$output_file" 2>/dev/null

# Persistencia
print_red "###############################################     " >> "$output_file"
print_red "####                                       ####     " >> "$output_file"
print_red "####            Persistencia               ####     " >> "$output_file"
print_red "####                                       ####     " >> "$output_file"
print_red "###############################################     " >> "$output_file"
print_yellow "Chequeando posible Persistencia..." >> "$output_file"
print_yellow "---- Fichero .bashrc ----" >> "$output_file"
grep -vE '^\s*($|#)' ~/.bashrc | sed '/^\s*$/d' >> "$output_file" 2>/dev/null
print_yellow "---- Fichero .zshrc ----" >> "$output_file"
( grep -vE '^\s*($|#)' ~/.zshrc | sed '/^\s*$/d' >> "$output_file" ) 2>/dev/null
print_yellow "---- Lista de servicios,sockets,dispositivos y montajes ----" >> "$output_file"
systemctl >> "$output_file" 2>/dev/null
print_yellow "---- Tareas programadas por el usuario ----" >> "$output_file"
crontab -l >> "$output_file" 2>/dev/null
print_yellow "---- Tareas programadas periodicas ----" >> "$output_file"
{ cat anacrontab; echo -e "\n\n"; } >> "$output_file" 2>/dev/null

# Configuraciones
print_red "###############################################     " >> "$output_file"
print_red "####                                       ####     " >> "$output_file"
print_red "####      Configuracion de la maquina      ####     " >> "$output_file"
print_red "####                                       ####     " >> "$output_file"
print_red "###############################################     " >> "$output_file"
print_yellow "---- Iptables ----" >> "$output_file"
iptables -L >> "$output_file" 2>/dev/null
print_yellow "---- Estado de UFW ----" >> "$output_file"
ufw status >> "$output_file" 2>/dev/null
print_yellow "Binarios en la carpeta  /usr/local/bin" >> "$output_file" 
ls -lah /usr/local/bin >> "$output_file" 2>/dev/null
print_yellow "Ficheros en la carpeta  /tmp" >> "$output_file" 
ls -lah /tmp >> "$output_file" 2>/dev/null
print_yellow "---- Paquetes instalados ----" >> "$output_file"
{ dpkg -l; echo -e "\n\n"; } >> "$output_file" 2>/dev/null

print_red "###############################################     " >> "$output_file"
print_red "####                                       ####     " >> "$output_file"
print_red "####        Carga dinamica de modulos      ####     " >> "$output_file"
print_red "####                                       ####     " >> "$output_file"
print_red "###############################################     " >> "$output_file"
print_yellow "---- Configuración de la variable de entorno LD_PRELOAD (uso para carga de .so maliciosas) ----" >> "$output_file"
env | grep LD_PRELOAD >> "$output_file" 2>/dev/null
print_yellow "---- La seccion .rodata de las bibliotecas compartidas .so son ----" >> "$output_file"
find / -type f -name '*.so*' -exec objdump -s -j .rodata {} + 2>/dev/null | grep -A 3 -B 1 LD_PRELOAD >> "$output_file" 2>/dev/null
print_yellow "---- Carga de modulos de kernel ----" >> "$output_file"
{ lsmod; echo -e "\n\n"; } >> "$output_file" 2>/dev/null

print_red "###############################################     " >> "$output_file"
print_red "####                                       ####     " >> "$output_file"
print_red "####      Archivos y accesos recientes     ####     " >> "$output_file"
print_red "####                                       ####     " >> "$output_file"
print_red "###############################################     " >> "$output_file"
print_yellow "---- 30 ultimos accesos/procesos ----" >> "$output_file"
find / -type f -atime -1 -printf "%TY-%Tm-%Td %TH:%TM:%.2TS %p\n" 2>/dev/null | sort -nr | head -n 30 >> "$output_file" 2>/dev/null
print_yellow "---- 30 ultimos ficheros creados en el sistema operativo ----" >> "$output_file"
find / -path '/run/user/1000/gvfs' -prune -o -path '/run/user/1000/doc' -prune -o -type f -perm -0001 -printf '%T@ %p\n' 2>/dev/null | sort -n -k 1 | head -n 30 | cut -d' ' -f 2- >> "$output_file" 2>/dev/null

print_red "######################################################################     " >> "$output_file"
print_red "####                                                              ####     " >> "$output_file"
print_red "####    Posible compromosiso de repositorios de actualizacion     ####     " >> "$output_file"
print_red "####                                                              ####     " >> "$output_file"
print_red "######################################################################     " >> "$output_file"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    case "$ID" in
        debian)
            # Repositorios normales de Debian
            debian_repos=("deb http://deb.debian.org/debian/ $VERSION_CODENAME main contrib non-free"
                           "deb-src http://deb.debian.org/debian/ $VERSION_CODENAME main contrib non-free")
            ;;
        ubuntu)
            # Repositorios normales de Ubuntu
            ubuntu_repos=("deb http://archive.ubuntu.com/ubuntu/ $UBUNTU_CODENAME main restricted universe multiverse"
                          "deb-src http://archive.ubuntu.com/ubuntu/ $UBUNTU_CODENAME main restricted universe multiverse")
            ;;
        kali)
            # Repositorios normales de Kali
            kali_repos=("deb https://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware"
                        "deb-src http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware")
            ;;
        *)
            echo "Sistema operativo no compatible"
            exit 1
            ;;
    esac

    # Función para verificar si un repositorio es normal
    es_repo_normal() {
        local repo="$1"
        for r in "${debian_repos[@]}" "${ubuntu_repos[@]}" "${kali_repos[@]}"; do
            if [ "$r" == "$repo" ]; then
                return 0
            fi
        done
        return 1
    }

    # Verificación de repositorios y escritura en el archivo de salida
    grep -vE '^\s*($|#)' /etc/apt/sources.list | while read -r line; do
        if es_repo_normal "$line"; then
            echo "$line" >> "$output_file"
        else
            echo "# MALICIOSO: $line" >> "$output_file"
        fi
    done

else
    echo "No se pudo determinar el sistema operativo"
    exit 1
fi

# Mensaje de confirmación
echo "Salida guardada en $output_file"