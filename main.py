import argparse
import json
import os
import sys
import time
from datetime import datetime
from typing import List, Dict
from scanner import scan_ports_multithread

def parse_ports(port_arg: str) -> List[int]:
    """
    Converte argumentos complexos de portas (ex: '80', '1-1024', '21,22,80', '1-100,5432,8080')
    em uma lista ordenada de inteiros sem duplicadas.
    """
    ports = set()
    try:
        # Divide por vírgulas primeiro
        parts = port_arg.split(",")
        for part in parts:
            part = part.strip()
            if "-" in part:
                start, end = map(int, part.split("-"))
                ports.update(range(start, end + 1))
            else:
                ports.add(int(part))
    except ValueError:
        print(f"[!] Erro: Formato de porta inválido '{port_arg}'. Use exemplos como '80', '1-1024' ou '1-100,5432'.")
        sys.exit(1)
        
    return sorted(list(ports))

def export_json(filename: str, target: str, scan_time: float, results: List[Dict]):
    """Gera um relatório estruturado no formato JSON."""
    data = {
        "metadata": {
            "target": target,
            "timestamp": datetime.now().isoformat(),
            "scan_duration_seconds": round(scan_time, 2),
            "total_open_ports": len(results)
        },
        "open_ports": results
    }
    with open(filename, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)
    print(f"[+] Relatório JSON exportado com sucesso: {filename}")

def export_markdown(filename: str, target: str, scan_time: float, results: List[Dict]):
    """Gera um relatório executivo formatado em Markdown."""
    lines = [
        f"# Relatório de Auditoria de Superfície de Ataque",
        f"**Alvo:** `{target}`  ",
        f"**Data/Hora:** `{datetime.now().strftime('%d/%m/%Y %H:%M:%S')}`  ",
        f"**Tempo de Varredura:** `{scan_time:.2f}s`  ",
        f"**Total de Portas Abertas:** `{len(results)}`  \n",
        "---",
        "## Serviços e Portas Identificados\n",
        "| Porta | Serviço | Nível de Risco | Descrição / Detalhes |",
        "|---|---|---|---|"
    ]
    
    for item in results:
        lines.append(f"| `{item['port']}` | {item['service']} | **{item['risk']}** | {item['description']} |")

    lines.append("\n### Recomendações de Segurança")
    lines.append("- **Acesso Privado:** Garanta que serviços de banco de dados e gestão (como PostgreSQL ou MSRPC) não estejam expostos para redes públicas.")
    lines.append("- **Firewall:** Configure regras de firewall locais (UFW / Windows Firewall) para bloquear portas não essenciais.")

    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"[+] Relatório Markdown exportado com sucesso: {filename}")

def main():
    parser = argparse.ArgumentParser(
        description="Network Recon & Port Scanner CLI Tool — Auditoria de Superfície de Ataque"
    )
    
    parser.add_argument("-t", "--target", required=True, help="Endereço IP ou hostname do alvo (ex: 127.0.0.1)")
    parser.add_argument("-p", "--ports", default="1-1024", help="Faixa de portas (ex: '1-1024', '80', '1-100,5432'). Padrão: 1-1024")
    parser.add_argument("--threads", type=int, default=100, help="Número de threads concorrentes (Padrão: 100)")
    parser.add_argument("--timeout", type=float, default=1.0, help="Timeout das conexões em segundos (Padrão: 1.0)")
    parser.add_argument("-o", "--output", choices=["json", "md", "both"], help="Exportar relatório: 'json', 'md' ou 'both'")

    args = parser.parse_args()
    port_list = parse_ports(args.ports)

    print("=" * 70)
    print(f"[*] RECON CLI TOOL — INICIANDO VARREDURA")
    print(f"[*] Alvo: {args.target}")
    print(f"[*] Portas a testar: {len(port_list)} portas")
    print(f"[*] Threads: {args.threads} | Timeout: {args.timeout}s")
    print("=" * 70 + "\n")

    inicio = time.time()
    
    try:
        resultados = scan_ports_multithread(
            ip=args.target, 
            ports=port_list, 
            max_threads=args.threads, 
            timeout=args.timeout
        )
    except KeyboardInterrupt:
        print("\n[!] Varredura interrompida pelo usuário (Ctrl+C). Exiting...")
        sys.exit(0)

    fim = time.time()
    duracao = fim - inicio

    print(f"[+] Varredura concluída em {duracao:.2f} segundos!\n")
    
    if not resultados:
        print("[-] Nenhuma porta aberta foi encontrada no intervalo especificado.")
        return

    print(f"{'PORTA':<8} {'SERVIÇO':<12} {'RISCO':<10} {'DESCRIÇÃO'}")
    print("-" * 70)
    for item in resultados:
        print(f"{item['port']:<8} {item['service']:<12} {item['risk']:<10} {item['description']}")
        if item['banner'] != "Banner indisponível":
            print(f"         └─ Banner: {item['banner'][:50]}")
    print("-" * 70 + "\n")

    # Exportação de Relatórios
    if args.output in ["json", "both"]:
        export_json("scan_report.json", args.target, duracao, resultados)
        
    if args.output in ["md", "both"]:
        export_markdown("scan_report.md", args.target, duracao, resultados)

if __name__ == "__main__":
    main()