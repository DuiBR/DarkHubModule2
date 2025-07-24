#!/bin/bash

directory="/opt/darkapi"

# Define cores para saída
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

# Função para registrar cabeçalhos
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
domains_default="localhost"
port_default="3000"
server_token_default="meu_token_padrao"
ipaceito_default="127.0.0.1"

# Atribuição com valores padrão
domains=${1:-$domains_default}
port=${2:-$port_default}
server_token=${3:-$server_token_default}
ipaceito=${4:-$ipaceito_default}

# Log das configurações
log_header "Configurações"
log_message "🌐 Domínios: $domains"
log_message "🔌 Porta: $port"
log_message "🔑 Server Token: $server_token"
log_message "📡 IP Aceito: $ipaceito"

# === MELHORIA NO SISTEMA DE DOWNLOAD ===
log_header "Baixando arquivos necessários"

# Função para tentar download com múltiplas fontes
download_file() {
    local file_name=$1
    local output_path=$2
    local max_retries=3
    local retry_count=0
    local success=0
    
    # Lista de fontes alternativas
    local sources=(
        "https://raw.githubusercontent.com/DuiBR/DarkHubModule2/main/$file_name"
        "https://cdn.jsdelivr.net/gh/DuiBR/DarkHubModule2@main/$file_name"
        "https://gitlab.com/DuiBR/DarkHubModule2/-/raw/main/$file_name"
    )
    
    while [ $retry_count -lt $max_retries ] && [ $success -eq 0 ]; do
        for source in "${sources[@]}"; do
            log_message "🔹 Tentando baixar de: $source"
            if wget -q -O "$output_path" "$source"; then
                success=1
                log_message "✅ Download bem-sucedido de $source"
                break
            else
                log_message "🔸 Falha com $source"
            fi
            sleep 1
        done
        
        if [ $success -eq 0 ]; then
            ((retry_count++))
            log_message "🔄 Tentativa $retry_count de $max_retries falhou. Tentando novamente..."
            sleep 3
        fi
    done
    
    return $((1 - success))
}

# Baixar arquivos essenciais
download_file "modulo.zip" "$ZIP_FILE"
zip_status=$?

# Verificação crítica do arquivo zip
if [ $zip_status -ne 0 ]; then
    log_message "❌❌❌ FALHA CRÍTICA: Não foi possível baixar modulo.zip após múltiplas tentativas"
    log_message "⚠️ Por favor, verifique sua conexão com a internet e tente novamente"
    log_message "⚠️ Se o problema persistir, contate o suporte"
    exit 1
fi

# Baixar outros arquivos (não críticos)
download_file "modulosinstall.sh" "/root/modulosinstall.sh"
download_file "limpar_usuarios_tudo.sh" "/opt/darkapi/limpar_usuarios_tudo.sh"

if [ -f "/opt/darkapi/limpar_usuarios_tudo.sh" ]; then
    chmod +x /opt/darkapi/limpar_usuarios_tudo.sh
    log_message "✅ limpar_usuarios_tudo.sh baixado e permissões ajustadas"
fi

# Remove domínios antigos do hosts
log_header "Atualizando arquivos de hosts"
sed -i "/$domains/d" /etc/hosts 2>/dev/null
sed -i "/$domains/d" /etc/cloud/templates/hosts.debian.tmpl 2>/dev/null

# Função para verificar se o comando existe
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

log_header "Verificando firewall e dependências"

# Firewall (continua mesmo se não encontrar)
for fw in firewalld iptables ufw; do
    if command_exists "$fw"; then
        log_message "✅ $fw instalado."
    else
        log_message "⚠️ $fw não encontrado. Continuando sem firewall."
    fi
done

log_header "Verificando e instalando dependências do sistema"
sudo apt-get update -qq > /dev/null 2>&1
sudo apt-get install -y -qq python3 python3-pip python3-venv python3-distutils curl unzip wget git dos2unix zip tar nano lsof net-tools sudo cron jq bc > /dev/null 2>&1
log_status $? "Dependências instaladas/verificadas" "Algumas dependências podem ter falhado"

log_header "Parando e desabilitando serviços antigos"
for padrao in 'modulo*.service' 'ModuloSinc*.service' 'ModuloCron*.service'; do
    services=$(systemctl list-units --type=service --no-legend "$padrao" 2>/dev/null | awk '{print $1}' | grep -v -e '^$' -e '^unknown$' -e '^UNIT$')
    if [ -n "$services" ]; then
        for service in $services; do
            if [[ -n "$service" && "$service" != "unknown" ]]; then
                systemctl stop "$service" >/dev/null 2>&1
                systemctl disable "$service" >/dev/null 2>&1
                log_message "🔸 Parado e desabilitado: $service"
            fi
        done
    else
        log_message "🔸 Nenhum serviço encontrado com padrão $padrao."
    fi
done

log_header "Salvando domínios no arquivo"
for domain in $(echo $domains | tr "," "\n"); do
    if ! grep -qx "$domain" "$DOMAINS_FILE"; then
        echo "$domain" >> "$DOMAINS_FILE"
        log_message "🌐 Domínio adicionado: $domain"
    else
        log_message "🌐 Domínio já existe: $domain"
    fi
done

log_header "Configurando firewall para a porta $port (TCP/UDP)"
if command_exists firewall-cmd; then
    sudo firewall-cmd --zone=public --add-port=${port}/tcp --permanent >/dev/null 2>&1
    sudo firewall-cmd --zone=public --add-port=${port}/udp --permanent >/dev/null 2>&1
    sudo firewall-cmd --reload >/dev/null 2>&1
    log_status $? "firewalld atualizado!" "Falha no firewalld."
fi

if command_exists iptables; then
    sudo iptables -D INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1
    sudo iptables -D INPUT -p udp --dport "$port" -j ACCEPT >/dev/null 2>&1
    sudo iptables -A INPUT -p tcp --dport "$port" -j ACCEPT >/dev/null 2>&1
    sudo iptables -A INPUT -p udp --dport "$port" -j ACCEPT >/dev/null 2>&1
    sudo iptables-save | sudo tee /etc/iptables/rules.v4 >/dev/null 2>&1
    if systemctl list-units --type=service | grep -qw netfilter-persistent; then
        sudo systemctl reload netfilter-persistent >/dev/null 2>&1
    fi
    log_status $? "iptables atualizado!" "Falha ao atualizar iptables."
fi

if command_exists ufw; then
    sudo ufw allow $port/tcp >/dev/null 2>&1
    sudo ufw allow $port/udp >/dev/null 2>&1
    sudo ufw reload >/dev/null 2>&1
    log_status $? "ufw atualizado!" "Falha ao atualizar ufw."
fi

log_header "Descompactando módulos"
if [ -f "$ZIP_FILE" ]; then
    unzip -o "$ZIP_FILE" -d /opt/darkapi/ >/dev/null 2>&1
    if [ $? -eq 0 ]; then
        log_message "✅ Módulos descompactados com sucesso."
        
        # Verifica se os arquivos essenciais existem
        essential_files=("ModuloSinc" "ModuloCron.sh" "CorrecaoV2.py")
        missing_files=0
        
        for file in "${essential_files[@]}"; do
            if [ ! -f "/opt/darkapi/$file" ]; then
                log_message "❌ $file NÃO encontrado após descompactação!"
                ((missing_files++))
            fi
        done
        
        if [ $missing_files -gt 0 ]; then
            log_message "⚠️ ATENÇÃO: $missing_files arquivos essenciais faltando no ZIP!"
            log_message "⚠️ O módulo pode não funcionar corretamente"
        fi
    else
        log_message "❌ Erro ao descompactar módulos. Código de erro: $?"
        log_message "⚠️ Tentando forçar a descompactação com unzip -F"
        unzip -F -o "$ZIP_FILE" -d /opt/darkapi/ >> "$LOG_FILE" 2>&1
        if [ $? -eq 0 ]; then
            log_message "✅ Descompactação forçada bem-sucedida"
        else
            log_message "❌❌ Falha crítica na descompactação. Abortando instalação."
            exit 1
        fi
    fi
else
    log_message "❌ Arquivo $ZIP_FILE não encontrado. Abortando."
    exit 1
fi

echo '{"comandos_proibidos": ["rm", "dd", "mkfs", "poweroff", "init", "reboot", "shutdown", "useradd", "passwd", "chpasswd", "usermod", "adduser", "groupadd", "chown", "chmod", "perl", "php", "systemctl", "visudo", "scp", "nc", "ncat", "socat"]}' > /opt/darkapi/comandos_bloqueados.json
echo '{"ips": ["127.0.0.1", "'$ipaceito'"]}' > /opt/darkapi/ips_autorizados.json

cat << EOF > /etc/systemd/system/ModuloSinc.service
[Unit]
Description=ModuloSinc UDP Server
After=network.target

[Service]
Type=simple
ExecStart=/opt/darkapi/ModuloSinc $server_token $port
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat << EOF > /etc/systemd/system/ModuloCron.service
[Unit]
Description=Modulo Service
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash /opt/darkapi/ModuloCron.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat << EOF > /opt/darkapi/ModuloCron.sh
#!/bin/bash

DOMS="/opt/darkapi/dominios.txt"
while read -r domain; do
  while true; do
    curl -s --ipv4 -X POST \
      -H "Host: \$domain" \
      -d "servertoken=$server_token" \
      "http://$ipaceito/crons.php" > /dev/null
    sleep 3
  done &
done < \$DOMS
wait
EOF

log_header "Aplicando dos2unix em todos os arquivos"
if command_exists dos2unix; then
    find /opt/darkapi -type f -exec dos2unix {} \; >/dev/null 2>&1
    log_status $? "Conversão dos2unix aplicada com sucesso." "Erro: dos2unix não está instalado."
else
    log_message "⚠️ Aviso: dos2unix não está instalado. Pulando conversão."
fi

log_header "Ajustando permissões"
chmod -R 777 /opt/darkapi >/dev/null 2>&1
chmod 777 /etc/systemd/system/ModuloSinc.service /etc/systemd/system/ModuloCron.service >/dev/null 2>&1

log_header "Reiniciando e habilitando serviços"
systemctl daemon-reload >/dev/null 2>&1
systemctl enable ModuloSinc.service >/dev/null 2>&1
systemctl start ModuloSinc.service >/dev/null 2>&1
systemctl restart ModuloSinc.service >/dev/null 2>&1
systemctl enable ModuloCron.service >/dev/null 2>&1
systemctl start ModuloCron.service >/dev/null 2>&1
systemctl restart ModuloCron.service >/dev/null 2>&1
log_message "✅ Serviço ModuloSinc.service e ModuloCron.service reiniciados e habilitados com sucesso."

log_header "Executando scripts adicionais"
sleep 1
if [ -f "/opt/darkapi/CorrecaoV2.py" ]; then
    log_message "Executando CorrecaoV2"
    sudo python3 /opt/darkapi/CorrecaoV2.py >> $LOG_FILE 2>&1
    log_status $? "CorrecaoV2 executado com sucesso" "Falha ao executar CorrecaoV2"
else
    log_message "❌ CorrecaoV2.py não encontrado. Pulando execução."
fi

log_header "Limpando arquivos temporários"
rm -f $ZIP_FILE /root/modulosinstall.sh >/dev/null 2>&1

log_header "INSTALAÇÃO E CONFIGURAÇÃO CONCLUÍDAS"
echo "comandoenviadocomsucesso"