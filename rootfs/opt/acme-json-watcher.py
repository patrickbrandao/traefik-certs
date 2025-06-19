#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
import time
import signal
import subprocess
import logging
import json
import base64
import hashlib

from pathlib import Path

# Variáveis globais com os valores padrão
json_path = "/etc/letsencrypt/acme.json"
save_dir = "/data/certs"
hook_script = "/opt/sync-task.sh"
action = "watch"

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('acme-json-watcher')


#----------------------------------------------------------------------------- importacao de json

# Obter MD5 de um arquivo
def calculate_and_save_md5(file_path):
    """
    Calcula o MD5 de um arquivo e salva o resultado em um arquivo com extensão .md5
    
    Args:
        file_path (str): Caminho completo para o arquivo a ser processado
        
    Returns:
        str: O hash MD5 do arquivo em formato hexadecimal
    
    Raises:
        FileNotFoundError: Se o arquivo de origem não existir
        PermissionError: Se não tiver permissão para ler o arquivo ou escrever o arquivo MD5
    """
    try:
        # Verifica se o arquivo existe
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"O arquivo {file_path} não foi encontrado")

        # Calcula o MD5 do arquivo
        md5_hash = hashlib.md5()
        with open(file_path, "rb") as f:
            # Lê o arquivo em blocos para evitar consumo excessivo de memória
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
                
        # Obtém o MD5 em formato hexadecimal
        md5_hex = md5_hash.hexdigest()
        
        # Cria o nome do arquivo MD5 (troca a extensão para .md5)
        # Quando o arquivo tem múltiplos pontos, considera apenas o último como início da extensão
        file_dir = os.path.dirname(file_path)
        file_name = os.path.basename(file_path)
        last_dot_index = file_name.rfind('.')
        
        if last_dot_index != -1:
            # Nome do arquivo tem pelo menos um ponto
            base_name = file_name[:last_dot_index]
            md5_file_name = base_name + ".md5"
        else:
            # Nome do arquivo não tem pontos
            md5_file_name = file_name + ".md5"
            
        md5_file_path = os.path.join(file_dir, md5_file_name)
        
        # Salva o MD5 no arquivo
        with open(md5_file_path, "w") as md5_file:
            md5_file.write(md5_hex)
            
        return md5_hex
        
    except FileNotFoundError:
        raise
    except PermissionError:
        raise PermissionError(f"Sem permissão para ler o arquivo {file_path} ou escrever {md5_file_path}")
    except Exception as e:
        raise Exception(f"Erro ao processar o arquivo: {str(e)}")
    # end - calculate_and_save_md5

# Obter certificado principal e chain posterior
def split_certificates(text):
    """
    Divide um texto contendo múltiplos certificados em dois componentes:
    - O primeiro certificado
    - Os certificados intermediários (do segundo ao último)
    
    Args:
        text (str): Texto contendo os certificados no formato PEM
        
    Returns:
        dict: Um dicionário com as chaves 'cert' e 'chain'
    """
    # Constantes para identificar o início e fim de cada certificado
    BEGIN_CERT = "-----BEGIN CERTIFICATE-----"
    END_CERT = "-----END CERTIFICATE-----"
    
    # Encontrar todos os certificados no texto
    certificates = []
    start_index = 0
    
    while True:
        # Encontrar o início do próximo certificado
        start = text.find(BEGIN_CERT, start_index)
        if start == -1:
            break
        
        # Encontrar o fim do certificado
        end = text.find(END_CERT, start) + len(END_CERT) + 1
        if end == -1 + len(END_CERT):  # Não encontrou o fim
            break
        
        # Extrair o certificado completo (incluindo as tags de início e fim)
        cert = text[start:end]
        certificates.append(cert)

        # Atualizar o índice de início para a próxima busca
        start_index = end
    
    # Verificar se encontramos pelo menos um certificado
    if not certificates:
        return {"cert": "", "chain": ""}
    
    # O primeiro certificado vai para 'cert'
    first_cert = certificates[0]
    
    # Os certificados restantes (se houver) vão para 'chain'
    if len(certificates) > 1:
        # Juntar os certificados intermediários com quebras de linha entre eles
        chain_certs = "\n\n".join(certificates[1:])
    else:
        chain_certs = ""

    return {
        "cert": first_cert.encode('utf-8') if first_cert else b"",
        "chain": chain_certs.encode('utf-8') if chain_certs else b""
    }
    #return {
    #    "cert": first_cert,
    #    "chain": chain_certs
    #}
    # end - split_certificates

# Criar diretorio
def makedir(dir_path):
    # Verifica se o diretório de saída existe e tenta criá-lo se não existir
    if not os.path.exists(dir_path):
        try:
            os.makedirs(dir_path)
        except Exception as e:
            return False
    return True
    # end - makedir

# Gravar conteudo em arquivo
def file_put_content(dst_file, content):
    """Decodifica conteúdo base64 e salva em um arquivo."""
    try:
        with open(dst_file, 'wb') as f:
            f.write(content)
        logger.info(f"file_put_content - Arquivo salvo: {dst_file}")
        return True
    except Exception as e:
        logger.info(f"file_put_content - Erro ao decodificar e salvar: {dst_file}: {str(e)}")
        return False
    # end - file_put_content

# Carregar arquivo JSON e processar certificados declarados
def process_acme_json():
    """Processa o arquivo acme.json e extrai certificados e chaves."""

    # Carrega o arquivo acme.json
    try:
        with open(json_path, 'r') as f:
            acme_data = json.load(f)
    except Exception as e:
        logger.info(f"process_acme_json - Erro ao ler o arquivo JSON {json_path}: {str(e)}")
        return;

    # Processa cada provedor no arquivo acme.json
    import_count = 0

    for provider, provider_data in acme_data.items():
        if "Certificates" not in provider_data:
            logger.info(f"process_acme_json - Aviso: Provedor {provider} não possui certificados.")
            continue
        
        for cert_entry in provider_data["Certificates"]:
            if "domain" not in cert_entry or "main" not in cert_entry["domain"]:
                logger.info("process_acme_json - Aviso: Entrada de certificado sem domínio principal encontrada. Ignorando.")
                continue

            # Importar somente certificado e cahve
            if "certificate" in cert_entry and cert_entry["certificate"] and "key" in cert_entry and cert_entry["key"]:
                import_count += 1
                # Nome do provedor do certificado ACME (minusculo)
                cloud_provider = provider.lower()

                # Nome do dominio FQDN (informacao do JSON)
                domain_fqdn    = cert_entry["domain"]["main"]

                # Certificado e chave privada (decodificar de base64 para texto PEM)
                domain_cert    = base64.b64decode(cert_entry["certificate"])
                domain_priv    = base64.b64decode(cert_entry["key"])

                # Separar o certificado do dominio do chain
                #cert_chain = split_certificates(domain_cert)
                cert_chain = split_certificates(domain_cert.decode('utf-8'))

                # - por dominio
                base_path      = f"{save_dir}/domains/{domain_fqdn}"
                cert_path      = f"{base_path}/cert.pem"
                makedir(base_path)
                file_put_content(f"{base_path}/fullchain.pem", domain_cert)
                file_put_content(f"{base_path}/privkey.pem",   domain_priv)
                file_put_content(f"{base_path}/chain.pem",     cert_chain["chain"])
                file_put_content(cert_path,                    cert_chain["cert"])
                calculate_and_save_md5(cert_path)

    logger.info(f"process_acme_json - Processamento concluido, certificados e chaves exportados: {import_count}")
    # end - process_acme_json
    # end - process_acme_json

#----------------------------------------------------------------------------- monitor de arquivo

def hook_execute():
    """
    Executa o script de sincronização fornecido
    """

    # Processa o arquivo acme.json
    process_acme_json()

    # Chamar script de hook para demais eventos
    try:
        logger.info(f"hook_execute - Executando o script: {hook_script}")
        # Executamos o script em um processo separado e não bloqueamos
        # A opção shell=False é mais segura e evita problemas de segurança
        result = subprocess.run([hook_script], check=False, capture_output=True, text=True)
        
        if result.returncode == 0:
            logger.info(f"hook_execute - Script executado com sucesso: {result.stdout.strip()}")
        else:
            logger.error(f"hook_execute - Script retornou código de erro {result.returncode}")
            if result.stderr:
                logger.error(f"hook_execute - Erro: {result.stderr}")
    except subprocess.SubprocessError as e:
        logger.error(f"hook_execute - Erro ao executar o script: {e}")
    except Exception as e:
        logger.error(f"hook_execute - Erro inesperado: {e}")
    
    # Não propagamos exceções para garantir que o monitoramento continue
    # end - hook_execute

def monitor_file_polling(check_interval=10):
    """
    Monitora um arquivo usando polling simples
    
    Args:
        check_interval: Intervalo em segundos entre as verificações
    """
    last_mtime = None
    last_size = None
    
    logger.info(f"monitor_file_polling - Iniciando monitoramento por polling para: {json_path}")
    logger.info(f"monitor_file_polling - Intervalo de verificação: {check_interval} segundos")
    
    while True:
        try:
            # Verifica se o arquivo existe
            if os.path.exists(json_path):
                # Obtém informações atuais do arquivo
                current_mtime = os.path.getmtime(json_path)
                current_size = os.path.getsize(json_path)
                
                # Se é a primeira verificação ou o arquivo mudou
                if (last_mtime is None or last_size is None or 
                    current_mtime != last_mtime or 
                    current_size != last_size):
                    
                    # Registra a alteração
                    logger.info(f"monitor_file_polling - Alteração detectada em: {json_path}")
                    if last_mtime is not None:
                        logger.info(f"monitor_file_polling - Timestamp anterior: {last_mtime}, novo: {current_mtime}")
                        logger.info(f"monitor_file_polling - Tamanho anterior: {last_size}, novo: {current_size}")
                    
                    # Atualiza os valores
                    last_mtime = current_mtime
                    last_size = current_size
                    
                    # Executa o script
                    hook_execute()
            else:
                # Se o arquivo existia antes e agora não existe
                if last_mtime is not None or last_size is not None:
                    logger.info(f"monitor_file_polling - Arquivo removido: {json_path}")
                    hook_execute()
                    
                # Reseta os valores
                last_mtime = None
                last_size = None
                
            # Espera pelo próximo intervalo
            time.sleep(check_interval)
            
        except Exception as e:
            logger.error(f"monitor_file_polling - Erro no monitoramento por polling: {e}")
            # Continua o loop mesmo em caso de erro
            time.sleep(check_interval)
    # end - monitor_file_polling

def wait_for_file(json_path):
    """
    Espera até que o arquivo exista
    
    Args:
        json_path (str): Caminho para o arquivo que deve existir
    """
    while not os.path.exists(json_path):
        logger.info(f"wait_for_file - Arquivo {json_path} não encontrado. Aguardando 1 minuto...")
        time.sleep(60)
    
    logger.info(f"wait_for_file - Arquivo {json_path} encontrado.")
    # end - wait_for_file

def setup_signal_handlers():
    """
    Configura manipuladores de sinal para encerramento limpo
    """
    def signal_handler(sig, frame):
        logger.info("setup_signal_handlers - Recebido sinal de término. Encerrando...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    # end - setup_signal_handlers

def main():
    """
    Função principal do programa
    """

    # Verifica os argumentos nas variaveis de ambiente
    global json_path, hook_script, save_dir, action

    # Verifica se as variáveis de ambiente estão definidas e não vazias; se sim, atualiza as variáveis globais
    env_json = os.getenv("TCERTS_ACME_JSON")
    if env_json:
        json_path = env_json

    env_sdir = os.getenv("TCERTS_SAVEDIR")
    if env_sdir:
        save_dir = env_sdir

    env_hook = os.getenv("TCERTS_HOOK_SCRIPT")
    if env_hook:
        hook_script = env_hook

    # Verificar se há argumentos e se o primeiro é "boot" ou "fetch"
    if len(sys.argv) > 1 and sys.argv[1] in ["boot", "fetch", "watch"]:
        action = sys.argv[1]
        logger.info(f"main - Procedimento definido: {action}")

    # Exibir o valor da variável action
    print(f"Action: {action}")

    # Restante do código utilizando json_path e hook_script
    logger.info(f"main - Caminho para o acme.json: {json_path}")
    logger.info(f"main - Caminho para diretorio de certificados: {save_dir}")
    logger.info(f"main - Caminho para o script de sincronismo: {hook_script}")
    logger.info(f"main - Procedimento acionado: {action}")

    # Verifica se o hook_script existe e tem permissão de execução
    if not os.path.exists(hook_script):
        logger.error(f"main - O script {hook_script} não existe.")
        sys.exit(1)
    
    if not os.access(hook_script, os.X_OK):
        logger.error(f"main - O script {hook_script} não tem permissão de execução.")
        sys.exit(1)
    
    # Garantir existencia do diretorio de saida dos certificados:
    makedir(save_dir)

    # Configura manipuladores de sinal
    setup_signal_handlers()

    # Procedimento on-shot
    # - Importar e chamar hook
    if action in ["boot"]:
        logger.info("main - Executando extracao de boot")
        process_acme_json()
        hook_execute()
        logger.info("main - Encerrando extracao de boot.")
        sys.exit(0)

    # - Apenas importar e encerrar
    if action in ["fetch"]:
        logger.info("main - Executando extracao de certicados")
        process_acme_json()
        logger.info("main - Encerrando processo de extracao de certicados.")
        sys.exit(0)

    # Define qual método de monitoramento usar
    # Por padrão, usamos polling, que é mais confiável em diferentes sistemas
    use_polling = True
    
    # Loop principal para garantir que o programa nunca termine
    while True:
        try:
            # Espera até que o arquivo exista
            wait_for_file(json_path)
            
            # Inicia o monitoramento com o método escolhido
            logger.info("main - Usando monitoramento por polling")
            monitor_file_polling()
            
            # Se por algum motivo o monitor retornar, esperamos um pouco e continuamos
            logger.warning("main - O monitoramento foi interrompido. Reiniciando em 10 segundos...")
            time.sleep(10)

        except KeyboardInterrupt:
            # Permite que o usuário interrompa o programa com Ctrl+C
            logger.info("main - Programa interrompido pelo usuário.")
            sys.exit(0)

        except Exception as e:
            logger.error(f"main - Erro no programa principal: {e}")
            logger.info("main - Reiniciando o programa em 10 segundos...")
            time.sleep(10)
            # Continuamos o loop para reiniciar o programa
    # end - main

if __name__ == "__main__":
    main()

