import socket
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict

RISK_PORTS = {
    21: {"service": "FTP", "risk": "ALTO", "desc": "Protocolo sem criptografia."},
    23: {"service": "Telnet", "risk": "CRÍTICO", "desc": "Acesso remoto sem criptografia."},
    135: {"service": "MSRPC", "risk": "MÉDIO", "desc": "Serviço RPC do Windows."},
    445: {"service": "SMB", "risk": "ALTO", "desc": "Compartilhamento de arquivos Windows."},
    1433: {"service": "MSSQL", "risk": "ALTO", "desc": "Banco de Dados SQL Server exposto."},
    3306: {"service": "MySQL", "risk": "ALTO", "desc": "Banco de Dados MySQL exposto."},
    3389: {"service": "RDP", "risk": "ALTO", "desc": "Área de Trabalho Remota do Windows."},
    5432: {"service": "PostgreSQL", "risk": "ALTO", "desc": "Banco de Dados PostgreSQL exposto."},
    6379: {"service": "Redis", "risk": "CRÍTICO", "desc": "Banco NoSQL sem autenticação por padrão."},
    27017: {"service": "MongoDB", "risk": "CRÍTICO", "desc": "Banco MongoDB exposto."}
}

def grab_banner(ip: str, port: int, timeout: float = 1.5) -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            if port in [80, 443, 8080, 8000]:
                s.sendall(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            return banner if banner else "Banner indisponível"
    except Exception:
        return "Banner indisponível"

def scan_port(ip: str, port: int, timeout: float = 1.0) -> Dict[str, any]:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        result = s.connect_ex((ip, port))
        
        if result == 0:
            banner = grab_banner(ip, port)
            risk_info = RISK_PORTS.get(port, {"service": "Genérico", "risk": "BAIXO", "desc": "Serviço padrão sem alerta direto."})
            
            return {
                "port": port,
                "open": True,
                "banner": banner,
                "service": risk_info["service"],
                "risk": risk_info["risk"],
                "description": risk_info["desc"]
            }
            
    return {"port": port, "open": False}

def scan_ports_multithread(ip: str, ports: List[int], max_threads: int = 50, timeout: float = 1.0) -> List[Dict]:
    open_services = []
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = [executor.submit(scan_port, ip, port, timeout) for port in ports]
        for future in futures:
            res = future.result()
            if res["open"]:
                open_services.append(res)
                
    return sorted(open_services, key=lambda x: x["port"])