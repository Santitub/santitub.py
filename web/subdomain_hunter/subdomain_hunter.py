#!/usr/bin/env python3
"""
Subdomain Hunter - Herramienta automatizada para Bug Bounty
Autor: Santitub
Versión: 1.1 - Optimizada para reducir timeouts
"""

import sys
import subprocess
import json
import time
from pathlib import Path
from urllib.parse import urlparse
from colorama import init, Fore, Style
import argparse
import asyncio
import aiohttp
import threading
from queue import Queue
import multiprocessing
import signal
import dns.resolver
import dns.exception

# Inicializar colorama
init(autoreset=True)

class SubdomainHunter:
    def __init__(self, domain, output_dir="output", threads=50, batch_size=100, rate_limit=50, proxy=None):
        self.max_workers = min(threads, multiprocessing.cpu_count() * 2)  # Reducido multiplicador
        self.session_timeout = aiohttp.ClientTimeout(total=15, connect=5)  # Timeouts más agresivos
        self.command_timeout = 120  # Timeout reducido de comandos
        self.chunk_timeout = 60    # Timeout específico para chunks
        self.semaphore = None
        self.results_queue = Queue()
        self.lock = threading.Lock()
        self.domain = domain
        self.output_dir = Path(output_dir)
        self.threads = threads
        self.subdomains = set()
        self.alive_subdomains = set()
        self.dns_resolved_subdomains = set() # Nueva estructura para subdominios que resuelven DNS
        self.batch_size = 100  # Tamaño de lote para procesamiento asíncrono
        self.rate_limit = 50  # Peticiones por segundo
        self.proxy = proxy
        self.proxy_dict = None
        if proxy:
            self.proxy_dict = self._parse_proxy(proxy)
        self.batch_size = batch_size
        self.scan_start_time = time.time()
        self.scan_data = {
            'domain': domain,
            'scan_date': time.strftime('%Y-%m-%d %H:%M:%S'),
            'total_subdomains': 0,
            'alive_subdomains': 0,
            'endpoints_by_category': {},
            'total_endpoints': 0,
            'scan_duration': 0,
            'tools_used': ['subfinder', 'crt.sh', 'waybackurls', 'httpx', 'katana', 'dnsx'],
            'dns_resolved_subdomains': 0,
        }
        self.endpoints = {
            'urls': set(), 'js': set(), 'php': set(), 'asp': set(), 'jsp': set(),
            'json': set(), 'xml': set(), 'pdf': set(), 'txt': set(), 'zip': set(),
            'sql': set(), 'bak': set(), 'log': set(), 'cfg': set(), 'yml': set(),
            'ini': set(), 'env': set(), 'py': set(), 'rb': set(), 'java': set(),
            'css': set(), 'html': set(), 'htm': set(), 'doc': set(), 'docx': set(),
            'xls': set(), 'xlsx': set(), 'ppt': set(), 'pptx': set(), 'csv': set(),
            'tar': set(), 'gz': set(), 'rar': set(), 'img': set(), 'png': set(),
            'jpg': set(), 'jpeg': set(), 'gif': set(), 'svg': set(), 'ico': set(),
            'woff': set(), 'woff2': set(), 'ttf': set(), 'eot': set()
        }
        
        # Configurar manejador de señales para timeouts
        signal.signal(signal.SIGALRM, self._timeout_handler)
        
        # Crear directorios
        self.setup_directories()
    
    def _parse_proxy(self, proxy_url):
        """Parsear URL de proxy y crear diccionario para requests/aiohttp"""
        try:
            if not proxy_url.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
                # Asumir HTTP si no se especifica protocolo
                proxy_url = f"http://{proxy_url}"
            
            parsed = urlparse(proxy_url)
            
            # Para requests (HTTP/HTTPS)
            if parsed.scheme in ['http', 'https']:
                return {
                    'http': proxy_url,
                    'https': proxy_url,
                    'type': 'http'
                }
            # Para SOCKS
            elif parsed.scheme in ['socks4', 'socks5']:
                return {
                    'http': proxy_url,
                    'https': proxy_url,
                    'type': 'socks'
                }
            else:
                self.log_warning(f"Tipo de proxy no soportado: {parsed.scheme}")
                return None
                
        except Exception as e:
            self.log_error(f"Error parseando proxy: {str(e)}")
            return None
        
    def _timeout_handler(self, signum, frame):
        """Manejador de timeout personalizado"""
        raise TimeoutError("Comando excedió el tiempo límite")
        
    def setup_directories(self):
        """Crear estructura de directorios"""
        self.output_dir.mkdir(exist_ok=True)
        (self.output_dir / "endpoints").mkdir(exist_ok=True)
        
    def print_banner(self):
        """Mostrar banner de la herramienta"""
        banner = f"""
{Fore.CYAN}{'='*60}
{Fore.YELLOW}
             ███████╗  ██╗  ██╗
            ██╔════╝   ██║  ██║
            ███████╗   ███████║
            ╚════██╗   ██╔══██║
            ███████║   ██║  ██║
            ╚══════╝   ╚═╝  ╚═╝ 
{Fore.GREEN}           🔍 Subdomain Hunter v1.1 🔍
{Fore.WHITE}         Optimized Bug Bounty Reconnaissance
{Fore.CYAN}{'='*60}

{Fore.YELLOW}Target Domain: {Fore.WHITE}{self.domain}
{Fore.YELLOW}Output Directory: {Fore.WHITE}{self.output_dir}
{Fore.YELLOW}Threads: {Fore.WHITE}{self.threads}
{Fore.YELLOW}Command Timeout: {Fore.WHITE}{self.command_timeout}s
{Fore.CYAN}{'='*60}
"""
        print(banner)

    def log_info(self, message):
        """Log información"""
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {message}")
        
    def log_success(self, message):
        """Log éxito"""
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {message}")
        
    def log_warning(self, message):
        """Log advertencia"""
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {message}")
        
    def log_error(self, message):
        """Log error"""
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}")

    def run_command_fast(self, command, description, timeout=None):
        """Ejecutar comando con timeout optimizado y manejo de errores mejorado"""
        if timeout is None:
            timeout = self.command_timeout
            
        self.log_info(f"Ejecutando: {description} (timeout: {timeout}s)")
        
        try:
            # Usar Popen para mejor control del proceso
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                preexec_fn=None if sys.platform == "win32" else lambda: signal.alarm(0)
            )
            
            try:
                stdout, stderr = process.communicate(timeout=timeout)
                
                if process.returncode == 0:
                    self.log_success(f"Completado: {description}")
                    return stdout.strip()
                else:
                    self.log_error(f"Error en {description}: {stderr[:200]}")
                    return ""
                    
            except subprocess.TimeoutExpired:
                # Terminar el proceso si excede el timeout
                process.kill()
                process.wait()
                self.log_warning(f"Timeout ({timeout}s) en {description} - proceso terminado")
                return ""
                
        except Exception as e:
            self.log_error(f"Excepción en {description}: {str(e)[:200]}")
            return ""

    def subfinder_scan_optimized(self):
        """Ejecutar subfinder con configuración optimizada"""
        self.log_info("🔍 Iniciando búsqueda con Subfinder (optimizada)...")
        
        subfinder_file = self.output_dir / "subfinder_results.txt"
        
        # Comando optimizado para subfinder
        command = f"timeout {self.command_timeout} subfinder -d {self.domain} -silent -t {self.threads} -timeout 10 -o {subfinder_file}"
        
        result = self.run_command_fast(command, "Subfinder scan optimizado", self.command_timeout + 10)
        
        # Leer resultados
        subs = set()
        if subfinder_file.exists():
            try:
                with open(subfinder_file, 'r') as f:
                    subs = set(line.strip() for line in f if line.strip())
            except Exception as e:
                self.log_error(f"Error leyendo subfinder results: {str(e)}")
        
        self.subdomains.update(subs)
        self.log_success(f"Subfinder encontró {len(subs)} subdominios")

    async def crtsh_scan_fast(self):
        """Búsqueda rápida en crt.sh con timeout reducido"""
        url = f"https://crt.sh/?q=%.{self.domain}&output=json"
        crt_subs = set()
        
        try:
            async with aiohttp.ClientSession(timeout=self.session_timeout) as session:
                async with session.get(url) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        for entry in data[:1000]:  # Limitar a primeros 1000 resultados
                            name_value = entry.get('name_value', '')
                            if name_value:
                                domains = name_value.split('\n')
                                for domain in domains:
                                    domain = domain.strip()
                                    if domain and self.domain in domain:
                                        if domain.startswith('*.'):
                                            domain = domain[2:]
                                        crt_subs.add(domain)
                        
        except Exception as e:
            self.log_warning(f"Error en crt.sh: {str(e)[:100]}")
            
        return crt_subs

    def crtsh_scan(self):
        """Wrapper síncrono para crt.sh optimizado"""
        self.log_info("🔍 Buscando en crt.sh (optimizado)...")
        
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            # Ejecutar con timeout
            crt_subs = loop.run_until_complete(
                asyncio.wait_for(self.crtsh_scan_fast(), timeout=30)
            )
            loop.close()
            
            self.subdomains.update(crt_subs)
            self.log_success(f"crt.sh encontró {len(crt_subs)} subdominios")
            
        except asyncio.TimeoutError:
            self.log_warning("crt.sh timeout - continuando con otros métodos")
        except Exception as e:
            self.log_error(f"Error en crt.sh: {str(e)[:100]}")

    def wayback_urls_fast(self):
        """Obtener URLs de Wayback Machine con timeout reducido"""
        self.log_info("🔍 Buscando URLs en Wayback Machine (rápido)...")
        
        wayback_file = self.output_dir / "wayback_urls.txt"
        
        # Comando con timeout específico
        command = f"timeout {self.chunk_timeout} bash -c 'echo {self.domain} | waybackurls | head -5000 > {wayback_file}'"
        
        result = self.run_command_fast(command, "Wayback URLs scan rápido", self.chunk_timeout + 5)
        
        wayback_subs = set()
        if wayback_file.exists():
            try:
                with open(wayback_file, 'r') as f:
                    urls = [line.strip() for line in f if line.strip()]
                    
                # Extraer subdominios de las URLs (máximo 1000)
                for url in urls[:1000]:
                    try:
                        parsed = urlparse(url)
                        if parsed.netloc and self.domain in parsed.netloc:
                            wayback_subs.add(parsed.netloc)
                    except:
                        continue
            except Exception as e:
                self.log_error(f"Error procesando wayback results: {str(e)}")
                
        self.subdomains.update(wayback_subs)
        self.log_success(f"Wayback Machine encontró {len(wayback_subs)} subdominios adicionales")
    
    async def dns_resolve_batch(self, subdomains_batch):
        """Resolver DNS para un lote de subdominios de forma asíncrona con rate limiting"""
        resolved = set()
        
        # Rate limiting para DNS
        delay_between_requests = 1.0 / self.rate_limit if self.rate_limit > 0 else 0
        
        for i, subdomain in enumerate(subdomains_batch):
            try:
                # Aplicar rate limiting
                if i > 0 and delay_between_requests > 0:
                    await asyncio.sleep(delay_between_requests)
                
                # Intentar resolver el subdominio
                resolver = dns.resolver.Resolver()
                resolver.timeout = 3
                resolver.lifetime = 5
                
                # Configurar DNS sobre proxy si está disponible (limitado)
                # Nota: DNS generalmente no se puede proxificar fácilmente
                
                # Intentar resolver A, AAAA, CNAME
                for record_type in ['A', 'AAAA', 'CNAME']:
                    try:
                        answers = resolver.resolve(subdomain, record_type)
                        if answers:
                            resolved.add(subdomain)
                            break
                    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
                        continue
                    except Exception:
                        continue
                        
            except Exception:
                continue
                
        return resolved

    async def dns_validate_async(self, subdomains_list):
        """Validar subdominios con DNS de forma asíncrona masiva"""
        if not subdomains_list:
            return set()
            
        # Dividir en lotes para procesamiento paralelo
        batches = [subdomains_list[i:i + self.batch_size] 
                  for i in range(0, len(subdomains_list), self.batch_size)]
        
        # Crear semáforo para limitar concurrencia
        semaphore = asyncio.Semaphore(20)  # Máximo 20 operaciones DNS simultáneas
        
        async def process_batch_with_semaphore(batch):
            async with semaphore:
                return await self.dns_resolve_batch(batch)
        
        # Ejecutar todos los lotes en paralelo
        results = await asyncio.gather(
            *[process_batch_with_semaphore(batch) for batch in batches],
            return_exceptions=True
        )
        
        # Combinar resultados
        all_resolved = set()
        for result in results:
            if isinstance(result, set):
                all_resolved.update(result)
                
        return all_resolved

    def dns_validation_fast(self):
        """Wrapper síncrono para validación DNS asíncrona"""
        self.log_info("🔍 Validando subdominios con DNS (asíncrono)...")
        
        if not self.subdomains:
            self.log_warning("No hay subdominios para validar")
            return
            
        try:
            # Convertir a lista para procesamiento
            subdomains_list = list(self.subdomains)
            
            # Ejecutar validación asíncrona
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            resolved_subs = loop.run_until_complete(
                asyncio.wait_for(
                    self.dns_validate_async(subdomains_list), 
                    timeout=300  # 5 minutos máximo
                )
            )
            loop.close()
            
            self.dns_resolved_subdomains.update(resolved_subs)
            
            # Actualizar subdominios principales con solo los que resuelven
            self.subdomains = self.dns_resolved_subdomains.copy()
            
            self.log_success(f"✅ DNS validó {len(self.dns_resolved_subdomains)} subdominios reales")
            
            # Guardar subdominios validados por DNS
            dns_validated_file = self.output_dir / "dns_validated_subdomains.txt"
            with open(dns_validated_file, 'w') as f:
                for sub in sorted(self.dns_resolved_subdomains):
                    f.write(f"{sub}\n")
            
            self.log_success(f"💾 Subdominios DNS validados guardados en {dns_validated_file}")
            
        except asyncio.TimeoutError:
            self.log_warning("DNS validation timeout - usando subdominios sin validar")
        except Exception as e:
            self.log_error(f"Error en validación DNS: {str(e)[:100]}")

    def save_subdomains(self):
        """Guardar todos los subdominios encontrados"""
        subdomains_file = self.output_dir / "subdomains.txt"
        
        # Ordenar y limpiar subdominios
        clean_subs = sorted(list(self.subdomains))
        
        with open(subdomains_file, 'w') as f:
            for sub in clean_subs:
                f.write(f"{sub}\n")
                
        self.log_success(f"💾 Guardados {len(clean_subs)} subdominios únicos en {subdomains_file}")

    def check_alive_subdomains_fast(self):
        """Verificar subdominios activos con procesamiento asíncrono avanzado, rate limiting y proxy"""
        self.log_info("🔍 Verificando subdominios activos (asíncrono masivo)...")
        
        if self.proxy:
            self.log_info(f"🔄 Verificación a través de proxy: {self.proxy}")
        if self.rate_limit:
            self.log_info(f"⚡ Rate limiting: {self.rate_limit} peticiones/segundo")
        
        if not self.subdomains:
            self.log_error("No hay subdominios para verificar")
            return
        
        try:
            # Usar subdominios DNS validados si existen, sino usar todos
            subdomains_to_check = list(self.dns_resolved_subdomains if self.dns_resolved_subdomains 
                                     else self.subdomains)
            
            # Ejecutar verificación asíncrona
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            
            alive_urls = loop.run_until_complete(
                asyncio.wait_for(
                    self.check_alive_async(subdomains_to_check),
                    timeout=600  # 10 minutos máximo
                )
            )
            loop.close()
            
            # Extraer dominios de las URLs activas
            for url in alive_urls:
                try:
                    parsed = urlparse(url)
                    if parsed.netloc:
                        self.alive_subdomains.add(parsed.netloc)
                except:
                    continue
            
            # Guardar resultados
            alive_file = self.output_dir / "alive_subdomains.txt"
            with open(alive_file, 'w') as f:
                for url in sorted(alive_urls):
                    f.write(f"{url}\n")
                    
            self.log_success(f"✅ Encontrados {len(self.alive_subdomains)} subdominios activos (async)")
            
        except asyncio.TimeoutError:
            self.log_warning("HTTP check timeout - usando fallback")
            # Fallback al método original si falla
            self._fallback_httpx_check()
        except Exception as e:
            self.log_error(f"Error en verificación async: {str(e)[:100]}")
            self._fallback_httpx_check()

    def _fallback_httpx_check(self):
        """Método de respaldo usando httpx tradicional con proxy support"""
        subdomains_file = self.output_dir / "subdomains.txt"
        alive_file = self.output_dir / "alive_subdomains.txt"
        
        if subdomains_file.exists():
            # Construir comando httpx con proxy si está disponible
            command = f"timeout {self.command_timeout} httpx -l {subdomains_file} -silent -threads {self.threads} -timeout 5 -retries 1 -rate-limit {self.rate_limit}"
            
            # Añadir proxy si está configurado y es HTTP
            if self.proxy_dict and self.proxy_dict.get('type') == 'http':
                proxy_url = self.proxy_dict.get('http')
                command += f" -http-proxy {proxy_url}"
            
            command += f" -o {alive_file}"
            
            self.run_command_fast(command, "httpx verificación fallback con proxy", self.command_timeout + 10)
    
    async def httpx_check_batch(self, urls_batch):
        """Verificar lote de URLs con aiohttp, rate limiting y proxy support"""
        alive_urls = set()
        
        # Configurar connector con proxy si está disponible
        connector_kwargs = {'limit': 100, 'limit_per_host': 10}
        
        # Configurar proxy para aiohttp
        if self.proxy_dict and self.proxy_dict.get('type') == 'http':
            # aiohttp soporta HTTP/HTTPS proxies nativamente
            proxy_url = self.proxy_dict.get('http')
        else:
            proxy_url = None
            
        connector = aiohttp.TCPConnector(**connector_kwargs)
        timeout = aiohttp.ClientTimeout(total=10, connect=3)
        
        # Rate limiting
        delay_between_requests = 1.0 / self.rate_limit if self.rate_limit > 0 else 0
        
        try:
            session_kwargs = {
                'connector': connector,
                'timeout': timeout,
                'headers': {'User-Agent': 'SubdomainHunter/1.1'}
            }
            
            async with aiohttp.ClientSession(**session_kwargs) as session:
                
                # Crear tareas para todas las URLs del lote con rate limiting
                tasks = []
                for i, url in enumerate(urls_batch):
                    
                    # Aplicar delay para rate limiting
                    delay = i * delay_between_requests if delay_between_requests > 0 else 0
                    
                    if not url.startswith(('http://', 'https://')):
                        # Probar ambos protocolos
                        tasks.append(self._check_single_url_with_delay(session, f"https://{url}", delay, proxy_url))
                        tasks.append(self._check_single_url_with_delay(session, f"http://{url}", delay + 0.1, proxy_url))
                    else:
                        tasks.append(self._check_single_url_with_delay(session, url, delay, proxy_url))
                
                # Ejecutar todas las verificaciones en paralelo
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                # Procesar resultados
                for result in results:
                    if isinstance(result, str):  # URL válida
                        alive_urls.add(result)
                        
        except Exception as e:
            self.log_warning(f"Error en lote HTTP: {str(e)[:100]}")
            
        return alive_urls

    async def _check_single_url_with_delay(self, session, url, delay, proxy_url):
        """Verificar una sola URL con delay y proxy"""
        try:
            # Aplicar delay para rate limiting
            if delay > 0:
                await asyncio.sleep(delay)
                
            # Configurar proxy para la petición individual
            kwargs = {'allow_redirects': True}
            if proxy_url:
                kwargs['proxy'] = proxy_url
                
            async with session.get(url, **kwargs) as response:
                if 200 <= response.status < 400:
                    return url
        except Exception as e:
            # Log detallado para debugging de proxy
            if 'proxy' in str(e).lower():
                self.log_warning(f"Error de proxy para {url}: {str(e)[:50]}")
        return None

    async def _check_single_url(self, session, url):
        """Verificar una sola URL (método legacy - mantener compatibilidad)"""
        return await self._check_single_url_with_delay(session, url, 0, None)

    async def check_alive_async(self, subdomains_list):
        """Verificar subdominios activos de forma asíncrona masiva"""
        if not subdomains_list:
            return set()
            
        # Dividir en lotes
        batches = [subdomains_list[i:i + self.batch_size] 
                  for i in range(0, len(subdomains_list), self.batch_size)]
        
        # Procesar lotes en paralelo con semáforo
        semaphore = asyncio.Semaphore(10)  # Máximo 10 lotes simultáneos
        
        async def process_batch_with_semaphore(batch):
            async with semaphore:
                return await self.httpx_check_batch(batch)
        
        # Ejecutar verificación paralela
        results = await asyncio.gather(
            *[process_batch_with_semaphore(batch) for batch in batches],
            return_exceptions=True
        )
        
        # Combinar resultados
        all_alive = set()
        for result in results:
            if isinstance(result, set):
                all_alive.update(result)
                
        return all_alive

    def crawl_endpoints_fast(self):
        """Crawlear endpoints con katana optimizado para velocidad"""
        self.log_info("🕷️  Crawleando endpoints (rápido)...")
        
        alive_file = self.output_dir / "alive_subdomains.txt"
        if not alive_file.exists():
            self.log_error("No se encontró el archivo de subdominios activos")
            return
        
        endpoints_file = self.output_dir / "all_endpoints.txt"
        
        # Comando katana optimizado - profundidad reducida y más rápido
        command = f"timeout {self.command_timeout} katana -list {alive_file} -silent -d 1 -jc -c {self.threads} -rate-limit 100 -o {endpoints_file}"
        
        result = self.run_command_fast(command, "Katana crawling rápido", self.command_timeout + 10)
        
        # Procesar endpoints
        endpoints = []
        if endpoints_file.exists():
            try:
                with open(endpoints_file, 'r') as f:
                    endpoints = [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.log_error(f"Error leyendo endpoints: {str(e)}")
        
        self.log_success(f"🕷️  Crawleados {len(endpoints)} endpoints únicos")
        
        # Categorizar endpoints si hay resultados
        if endpoints:
            self.categorize_endpoints_fast(endpoints)

    def categorize_endpoints_fast(self, endpoints_list):
        """Categorizar endpoints de forma rápida"""
        self.log_info("📂 Categorizando endpoints (rápido)...")
        
        extension_map = {
            'js': 'js', 'php': 'php', 'asp': 'asp', 'jsp': 'jsp', 'json': 'json',
            'xml': 'xml', 'pdf': 'pdf', 'txt': 'txt', 'zip': 'zip', 'sql': 'sql',
            'bak': 'bak', 'log': 'log', 'cfg': 'cfg', 'yml': 'yml', 'ini': 'ini',
            'env': 'env', 'py': 'py', 'rb': 'rb', 'java': 'java', 'css': 'css',
            'html': 'html', 'htm': 'html', 'png': 'png', 'jpg': 'jpg', 'gif': 'gif'
        }
        
        # Procesar endpoints de forma más eficiente
        for url in endpoints_list[:5000]:  # Limitar para evitar overload
            try:
                parsed = urlparse(url)
                path = parsed.path.lower()
                
                if '.' in path:
                    extension = path.split('.')[-1].split('?')[0].split('#')[0]
                    
                    if extension in extension_map:
                        category = extension_map[extension]
                        self.endpoints[category].add(url)
                    else:
                        self.endpoints['urls'].add(url)
                else:
                    self.endpoints['urls'].add(url)
                    
            except:
                self.endpoints['urls'].add(url)
                continue
        
        # Guardar endpoints categorizados
        self.save_categorized_endpoints()

    def save_categorized_endpoints(self):
        """Guardar endpoints categorizados en archivos separados"""
        endpoints_dir = self.output_dir / "endpoints"
        
        for category, urls in self.endpoints.items():
            if urls:  # Solo crear archivo si hay URLs
                filename = endpoints_dir / f"{category}.txt"
                    
                try:
                    with open(filename, 'w') as f:
                        for url in sorted(urls):
                            f.write(f"{url}\n")
                    
                    self.log_success(f"📁 Guardados {len(urls)} endpoints .{category} en {filename}")
                except Exception as e:
                    self.log_error(f"Error guardando {category}: {str(e)}")

    def generate_json_output(self):
        """Generar output general en formato JSON"""
        self.log_info("📊 Generando output JSON...")
        
        try:
            # Actualizar datos del escaneo
            self.scan_data['total_subdomains'] = len(self.subdomains)
            self.scan_data['alive_subdomains'] = len(self.alive_subdomains)
            self.scan_data['scan_duration'] = round(time.time() - self.scan_start_time, 2)
            self.scan_data['dns_resolved_subdomains'] = len(self.dns_resolved_subdomains)
            
            # Contar endpoints por categoría
            for category, urls in self.endpoints.items():
                if urls:
                    self.scan_data['endpoints_by_category'][category] = len(urls)
            
            self.scan_data['total_endpoints'] = sum(self.scan_data['endpoints_by_category'].values())
            
            # Agregar listas (limitadas para evitar archivos enormes)
            self.scan_data['subdomains_list'] = sorted(list(self.subdomains))[:1000]
            self.scan_data['alive_subdomains_list'] = sorted(list(self.alive_subdomains))[:500]
            
            # Guardar JSON
            json_file = self.output_dir / "scan_results.json"
            with open(json_file, 'w', encoding='utf-8') as f:
                json.dump(self.scan_data, f, indent=2, ensure_ascii=False)
                
            self.log_success(f"💾 Output JSON guardado en {json_file}")
            
        except Exception as e:
            self.log_error(f"Error generando JSON: {str(e)}")

    def generate_html_report(self):
        """Generar reporte HTML optimizado"""
        self.log_info("📊 Generando reporte HTML...")
        
        try:
            html_content = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Subdomain Hunter Report - {self.domain}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }}
        .header {{ background: white; padding: 30px; border-radius: 10px; text-align: center; margin-bottom: 20px; }}
        .stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .stat-card {{ background: white; padding: 20px; border-radius: 10px; text-align: center; }}
        .stat-number {{ font-size: 2em; color: #007bff; font-weight: bold; }}
        .section {{ background: white; padding: 20px; margin-bottom: 20px; border-radius: 10px; }}
        .list {{ max-height: 300px; overflow-y: auto; background: #f8f9fa; padding: 10px; border-radius: 5px; }}
        .item {{ padding: 5px; margin: 2px 0; background: white; border-radius: 3px; font-family: monospace; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 Subdomain Hunter Report</h1>
        <p>Target: {self.domain} | Scan Date: {self.scan_data['scan_date']} | Duration: {self.scan_data['scan_duration']}s</p>
    </div>
    
    <div class="stats">
        <div class="stat-card">
            <div class="stat-number">{self.scan_data['total_subdomains']}</div>
            <div>Total Subdomains</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{self.scan_data['alive_subdomains']}</div>
            <div>Alive Subdomains</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{self.scan_data['total_endpoints']}</div>
            <div>Total Endpoints</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{self.scan_data.get('dns_resolved_subdomains', 0)}</div>
            <div>DNS Resolved</div>
        </div>
    </div>
    
    <div class="section">
        <h2>Discovered Subdomains (sample)</h2>
        <div class="list">
"""
            
            # Agregar muestra de subdominios
            sample_subs = list(self.subdomains)[:50]
            for sub in sample_subs:
                html_content += f'            <div class="item">{sub}</div>\n'
            
            if len(self.subdomains) > 50:
                html_content += f'            <div style="text-align: center; padding: 10px;">... y {len(self.subdomains) - 50} más</div>\n'
            
            html_content += """        </div>
    </div>
</body>
</html>"""
            
            # Guardar HTML
            html_file = self.output_dir / "report.html"
            with open(html_file, 'w', encoding='utf-8') as f:
                f.write(html_content)
                
            self.log_success(f"🌐 Reporte HTML guardado en {html_file}")
            
        except Exception as e:
            self.log_error(f"Error generando HTML: {str(e)}")

    def print_summary(self):
        """Mostrar resumen final"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.GREEN}           🎯 RESUMEN FINAL 🎯")
        print(f"{Fore.CYAN}{'='*60}")
        print(f"{Fore.YELLOW}Dominio objetivo: {Fore.WHITE}{self.domain}")
        print(f"{Fore.YELLOW}Total subdominios: {Fore.GREEN}{len(self.subdomains)}")
        print(f"{Fore.YELLOW}Subdominios activos: {Fore.GREEN}{len(self.alive_subdomains)}")
        print(f"{Fore.YELLOW}Subdominios DNS validados: {Fore.GREEN}{len(self.dns_resolved_subdomains)}")
        
        total_endpoints = sum(len(urls) for urls in self.endpoints.values())
        print(f"{Fore.YELLOW}Total endpoints: {Fore.GREEN}{total_endpoints}")
        print(f"{Fore.YELLOW}Tiempo total: {Fore.GREEN}{time.time() - self.scan_start_time:.2f}s")
        
        print(f"\n{Fore.CYAN}📁 ARCHIVOS GENERADOS:")
        files = [
            "subdomains.txt (todos los subdominios)",
            "alive_subdomains.txt (subdominios activos)", 
            "scan_results.json (output completo)",
            "report.html (reporte visual)",
            "endpoints/*.txt (endpoints por tipo)"
        ]
        
        for file in files:
            print(f"{Fore.GREEN}  ✓ {file}")
            
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"{Fore.GREEN}🎉 ¡Escaneo completado! 🎉")
        print(f"{Fore.CYAN}{'='*60}\n")

    def run(self):
        """Ejecutar el escaneo completo optimizado"""
        start_time = time.time()
        
        self.print_banner()
        
        try:
            # Fase 1: Descubrimiento de subdominios (secuencial para mejor control)
            self.log_info("🚀 FASE 1: Descubrimiento de subdominios")
            
            # Ejecutar búsquedas una por una para evitar timeouts simultáneos
            self.subfinder_scan_optimized()
            self.crtsh_scan()
            self.wayback_urls_fast()
            
            # Guardar subdominios combinados
            self.save_subdomains()

            self.log_info("🚀 FASE 1.5: Validación DNS de subdominios")
            if self.proxy:
                self.log_info(f"🔄 Usando proxy: {self.proxy}")
            self.log_info(f"⚡ Rate limit: {self.rate_limit} peticiones/segundo")
            self.dns_validation_fast()
            
            # Fase 2: Verificación de subdominios activos
            self.log_info("🚀 FASE 2: Verificación de subdominios activos")
            self.check_alive_subdomains_fast()
            
            # Fase 3: Crawling de endpoints (opcional, solo si hay subdominios activos)
            if len(self.alive_subdomains) > 0:
                self.log_info("🚀 FASE 3: Crawling de endpoints")
                self.crawl_endpoints_fast()
            else:
                self.log_warning("Sin subdominios activos - saltando crawling de endpoints")
            
            # Fase 4: Generar reportes
            self.log_info("🚀 FASE 4: Generando reportes")
            self.generate_json_output()
            self.generate_html_report()
            
            # Mostrar resumen
            self.print_summary()
            
        except KeyboardInterrupt:
            self.log_warning("❌ Escaneo interrumpido por el usuario")
            sys.exit(1)
        except Exception as e:
            self.log_error(f"Error inesperado: {str(e)}")
            sys.exit(1)

def main():
    parser = argparse.ArgumentParser(
        description="Buscador de subdominios optimizado para Bug Bounty",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  python subdomain_hunter.py -d example.com
  python subdomain_hunter.py -d example.com -o my_output -t 100
  
Versión optimizada con timeouts reducidos para evitar bloqueos.
        """
    )
    
    parser.add_argument(
        '-d', '--domain',
        required=True,
        help='Dominio objetivo (ej: example.com)'
    )
    
    parser.add_argument(
        '-o', '--output',
        default='output',
        help='Directorio de salida (default: output)'
    )
    
    parser.add_argument(
        '-t', '--threads',
        type=int,
        default=30,  # Reducido por defecto
        help='Número de threads (default: 30)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=120,
        help='Timeout para comandos en segundos (default: 120)'
    )

    parser.add_argument(
        '--batch-size',
        type=int,
        default=100,
        help='Tamaño de lote para procesamiento asíncrono (default: 100)'
    )
    
    parser.add_argument(
        '--rate',
        type=int,
        default=50,
        help='Rate limit - peticiones por segundo (default: 50)'
    )
    
    parser.add_argument(
        '--proxy',
        type=str,
        help='Proxy URL (soporta HTTP/HTTPS/SOCKS4/SOCKS5) - Ej: http://127.0.0.1:8080, socks5://127.0.0.1:1080'
    )
    
    args = parser.parse_args()
    
    # Validar dominio
    if not args.domain or '.' not in args.domain:
        print(f"{Fore.RED}[ERROR] Dominio inválido: {args.domain}")
        sys.exit(1)
    
    # Verificar herramientas requeridas
    required_tools = ['subfinder', 'httpx', 'katana', 'waybackurls', 'dnsx']
    missing_tools = []
    
    for tool in required_tools:
        try:
            subprocess.run([tool, '--help'], capture_output=True, timeout=5)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            missing_tools.append(tool)
    
    if missing_tools:
        print(f"{Fore.RED}[ERROR] Herramientas faltantes: {', '.join(missing_tools)}")
        print(f"{Fore.YELLOW}[INFO] Instala las herramientas faltantes antes de continuar")
        sys.exit(1)
    
    # Optimizar número de threads
    max_threads = multiprocessing.cpu_count() * 2
    if args.threads > max_threads:
        print(f"{Fore.YELLOW}[WARNING] Reduciendo threads de {args.threads} a {max_threads} para optimizar rendimiento")
        args.threads = max_threads
    
    # Iniciar escaneo
    hunter = SubdomainHunter(args.domain, args.output, args.threads, args.batch_size, args.rate, args.proxy)
    hunter.command_timeout = args.timeout
    if hasattr(args, 'batch_size'):
        hunter.batch_size = args.batch_size
    hunter.run()

if __name__ == "__main__":
    main()