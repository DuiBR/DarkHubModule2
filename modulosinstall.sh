#!/bin/bash

directory="/opt/darkapi"

# Define cores para saída (opcional)
green="\033[1;32m"
yellow="\033[1;33m"
red="\033[1;31m"
reset="\033[0m"

LOG_FILE="/opt/darkapi/instalacao.log"
DOMAINS_FILE="/opt/darkapi/dominios.txt"
ZIP_FILE="/root/modulos.zip"

[ ! -d /opt/darkapi ] && mkdir -p /opt/darkapi

# Função para registrar mensagens no log
log_message() {
    echo -e "$1" >> "$LOG_FILE"
}

# Função para registrar cabeçalhos bonitos
log_header() {
    log_message "\n==============================================================="
    log_message " $1"
    log_message "==============================================================="
}

# Função para logar sucesso/erro
log_status() {
    if [ "$1" -eq 0 ]; then
        log_message "✅ $2"
    else
        log_message "❌ $3"
    fi
}

log_header "INÍCIO DA INSTALAÇÃO - $(date '+%d/%m/%Y %H:%M:%S')"

# Limpa o log anterior e arquivos do diretório (exceto dominios.txt)
[ -f "$LOG_FILE" ] && rm "$LOG_FILE"
find "$directory" -type f ! -name 'dominios.txt' -exec rm -f {} + > /dev/null 2>&1

# Finaliza ModuloSinc
log_header "Finalizando processos ModuloSinc existentes"
pids=$(ps aux | grep '[M]oduloSinc' | awk '{print $2}' | grep -E '^[0-9]+$')
if [ -n "$pids" ]; then
    for pid in $pids; do
        if [[ "$pid" =~ ^[0-9]+$ ]]; then
            kill -9 "$pid" >/dev/null 2>&1
            log_message "🔸 Processo ModuloSinc encerrado (PID: $pid)"
        fi
    done
else
    log_message "🔸 Nenhum processo ModuloSinc em execução."
fi

# Fecha sockets TCP/UDP do ModuloSinc
socket_pids=$(lsof -nP -iUDP -iTCP 2>/dev/null | grep ModuloSinc | awk '{print $2}' | sort -u | grep -E '^[0-9]+$')
if [ -n "$socket_pids" ]; then
    for pid in $socket_pids; do
        if [[ "$pid" =~ ^[0-9]+$ ]]; then
            kill -9 "$pid" >/dev/null 2>&1
            log_message "🔸 Socket encerrado para ModuloSinc (PID: $pid)"
        fi
    done
fi

# Valores padrão
default_domains="localhost"
default_port="3000"
default_servertoken="meu_token_padrao"
default_ipaceito="127.0.0.1"

# Atribuir valores dos argumentos ou padrões
domains=${1:-$default_domains}
port=${2:-$default_port}
server_token=${3:-$default_servertoken}
ipaceito=${4:-$default_ipaceito}

# Remove domínios antigos do hosts (com tratamento de erro)
log_header "Atualizando arquivos de hosts"
# Verifica se o arquivo existe e tem permissão de escrita
if [ -w "/etc/hosts" ]; then
    sudo sed -i "/$domains/d" /etc/hosts 2>/dev/null
else
    log_message "⚠️ Não foi possível acessar /etc/hosts (permissões insuficientes)"
fi

if [ -w "/etc/cloud/templates/hosts.debian.tmpl" ]; then
    sudo sed -i "/$domains/d" /etc/cloud/templates/hosts.debian.tmpl 2>/dev/null
else
    log_message "⚠️ Não foi possível acessar /etc/cloud/templates/hosts.debian.tmpl"
fi

# Função para verificar se o comando existe
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

log_header "Verificando firewall e dependências"

# Firewall - apenas informativo
firewalls=("firewalld" "iptables" "ufw")
fw_found=0
for fw in "${firewalls[@]}"; do
    if command_exists "$fw"; then
        log_message "✅ $fw instalado."
        fw_found=1
    else
        log_message "⚠️ $fw não encontrado."
    fi
done

if [ "$fw_found" -eq 0 ]; then
    log_message "⚠️ Nenhum firewall detectado. Certifique-se de configurar manualmente a porta $port"
fi

log_header "Verificando e instalando dependências do sistema"
sudo apt-get update -qq > /dev/null 2>&1
sudo apt-get install -y -qq python3 python3-pip python3-venv python3-distutils curl unzip wget git dos2unix zip tar nano lsof net-tools sudo cron jq bc > /dev/null 2>&1
log_status $? "Dependências instaladas com sucesso" "Falha na instalação de dependências"

log_header "Parando e desabilitando serviços antigos"
services_found=0
for padrao in 'modulo*.service' 'ModuloSinc*.service' 'ModuloCron*.service'; do
    services=$(systemctl list-units --type=service --no-legend "$padrao" 2>/dev/null | awk '{print $1}' | grep -v -e '^$' -e '^unknown$' -e '^UNIT$')
    if [ -n "$services" ]; then
        for service in $services; do
            if [[ -n "$service" && "$service" != "unknown" ]]; then
                systemctl stop "$service" >/dev/null 2>&1
                systemctl disable "$service" >/dev/null 2>&1
                log_message "🔸 Parado e desabilitado: $service"
                services_found=1
            fi
        done
    fi
done

if [ "$services_found" -eq 0 ]; then
    log_message "🔸 Nenhum serviço antigo encontrado para remover."
fi

# Restante do script permanece igual...