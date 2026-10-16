# Network Recon & Port Scanner CLI Tool 🛠️

Ferramenta em linha de comando (CLI) desenvolvida em Python focada em reconhecimento de rede, auditoria de superfície de ataque e identificação de serviços expostos.

## 🚀 Funcionalidades
- **Varredura Concorrente Multithread:** Arquitetura baseada em `concurrent.futures.ThreadPoolExecutor` reduzindo o tempo de resposta em conexões TCP.
- **Banner Grabbing & Análise de Risco:** Captura de respostas de serviços e classificação automática de exposição de risco (ex.: PostgreSQL 5432, SMB 445, MSRPC 135).
- **Interface CLI Flexível:** Processamento dinâmico de argumentos de linha de comando (`argparse`) com suporte a múltiplos intervalos e portas individuais.
- **Geração de Relatórios Automática:** Exportação de achados em formatos estruturados (`JSON`) e executivos (`Markdown`).

## 🛠️ Tecnologias Utilizadas
- **Linguagem:** Python 3
- **Módulos Nativos:** `socket`, `concurrent.futures`, `argparse`, `json`, `datetime`

## 💻 Como Usar

### Pré-requisitos
Apenas o Python 3.x instalado (não requer instalação de bibliotecas externas de terceiros).

### Exemplos de Execução

1. **Varredura padrão (Portas 1-1024):**
`python main.py -t 127.0.0.1`

2. **Varredura com portas personalizadas e 100 threads:**
`python main.py -t 127.0.0.1 -p 1-1000,5432 --threads 100`

3. **Exportando relatórios (JSON e Markdown):**
`python main.py -t 127.0.0.1 -p 1-1000,5432 -o both`

4. **Menu de Ajuda:**
`python main.py --help`