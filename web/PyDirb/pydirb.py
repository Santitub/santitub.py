#!/usr/bin/env python3

"""
PyDirb - Herramienta de Directory Bruteforce
Una herramienta profesional para descubrir directorios y archivos ocultos en aplicaciones web.
"""

import argparse
import sys
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin, urlparse
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import urllib3
import colorama
from colorama import Fore, Back, Style
from tqdm import tqdm
import os
from collections import deque
import queue
import gc

# Suprimir advertencias SSL por defecto (se puede habilitar con --verify-ssl)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class RateLimiter:
    """Clase para controlar la tasa de peticiones por segundo."""
    
    def __init__(self, rate_limit):
        self.rate_limit = rate_limit  # peticiones por segundo
        self.min_interval = 1.0 / rate_limit if rate_limit > 0 else 0
        self.last_called = 0
        self.lock = threading.Lock()
    
    def wait(self):
        """Espera el tiempo necesario para respetar el rate limit."""
        if self.rate_limit <= 0:
            return
            
        with self.lock:
            elapsed = time.time() - self.last_called
            sleep_time = self.min_interval - elapsed
            if sleep_time > 0:
                time.sleep(sleep_time)
            self.last_called = time.time()


class PyDirb:
    """Clase principal para el escáner de directorios."""
    
    def __init__(self, target_url, wordlist_path, threads=10, rate_limit=0, 
                 extensions=None, output_file=None, status_codes=None, verify_ssl=False, proxy=None):
        self.target_url = target_url.rstrip('/')
        self.wordlist_path = wordlist_path
        self.threads = threads
        self.rate_limiter = RateLimiter(rate_limit)
        self.extensions = extensions or []
        self.output_file = output_file
        self.status_codes = status_codes or [200, 204, 301, 302, 307, 401, 403]
        self.verify_ssl = verify_ssl
        self.proxy = proxy
        
        # Estadísticas
        self.found_urls = []
        self.total_requests = 0
        self.successful_requests = 0
        
        # Control de output para barra de progreso
        self.progress_bar = None
        self.output_lock = threading.Lock()
        
        # Cola para URLs pendientes (limita el uso de memoria)
        self.url_queue = queue.Queue(maxsize=self.threads * 50)  # Buffer limitado
        self.results_processed = 0
        
        # Configurar sesión HTTP
        self.session = self._setup_session()
        
        # Inicializar colorama
        colorama.init(autoreset=True)
    
    def _setup_session(self):
        """Configura la sesión HTTP con reintentos y optimizaciones."""
        session = requests.Session()
        
        # Configurar reintentos
        retry_strategy = Retry(
            total=3,
            backoff_factor=0.3,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        
        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self.threads,
            pool_maxsize=self.threads * 2
        )
        
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Configurar proxy si se especificó
        if self.proxy:
            session.proxies.update({
                'http': self.proxy,
                'https': self.proxy
            })
        
        # Headers por defecto
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })
        
        return session
    
    def _update_user_agent(self, user_agent):
        """Actualiza el User-Agent de la sesión."""
        self.session.headers.update({'User-Agent': user_agent})
    
    def _count_wordlist_lines(self):
        """Cuenta las líneas válidas del diccionario sin cargar todo en memoria."""
        try:
            wordlist_file = Path(self.wordlist_path)
            if not wordlist_file.exists():
                self._print_error(f"El archivo de diccionario no existe: {self.wordlist_path}")
                return 0
            
            count = 0
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        count += 1
            
            return count
            
        except Exception as e:
            self._print_error(f"Error al contar líneas del diccionario: {e}")
            return 0
    
    def _load_wordlist_generator(self):
        """Generador que carga palabras del diccionario de forma lazy."""
        try:
            wordlist_file = Path(self.wordlist_path)
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        yield line
                        
        except Exception as e:
            self._print_error(f"Error al leer el diccionario: {e}")
            return
    
    def _generate_urls_generator(self, words_generator):
        """Generador que produce URLs de forma lazy a partir de palabras."""
        for word in words_generator:
            # URL básica sin extensión
            yield f"{self.target_url}/{word}"
            
            # URLs con extensiones
            for ext in self.extensions:
                if not ext.startswith('.'):
                    ext = '.' + ext
                yield f"{self.target_url}/{word}{ext}"
    
    def _make_request(self, url, timeout=10):
        """Realiza una petición HTTP a la URL especificada."""
        try:
            # Aplicar rate limiting
            self.rate_limiter.wait()
            
            response = self.session.get(
                url,
                timeout=timeout,
                allow_redirects=False,
                verify=self.verify_ssl  # Usar la configuración SSL del usuario
            )
            
            self.total_requests += 1
            return response
            
        except requests.exceptions.RequestException as e:
            self.total_requests += 1
            return None
    
    def _process_url(self, url):
        """Procesa una única URL y determina si es válida."""
        response = self._make_request(url)
        
        if response is None:
            return None
        
        status_code = response.status_code
        content_length = len(response.content)
        
        # Verificar si el código de estado es válido
        if status_code in self.status_codes:
            self.successful_requests += 1
            result = {
                'url': url,
                'status_code': status_code,
                'content_length': content_length,
                'response_time': response.elapsed.total_seconds()
            }
            return result
        
        return None
    
    def _print_banner(self):
        """Muestra el banner de la herramienta."""
        banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║                            PyDirb v1.0                       ║
║                    Directory Bruteforce Tool                 ║
╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
        print(banner)
    
    def _print_config(self):
        """Muestra la configuración actual del escaneo."""
        print(f"{Fore.YELLOW}[CONFIG]{Style.RESET_ALL} Target: {Fore.WHITE}{self.target_url}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[CONFIG]{Style.RESET_ALL} Wordlist: {Fore.WHITE}{self.wordlist_path}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[CONFIG]{Style.RESET_ALL} Threads: {Fore.WHITE}{self.threads}{Style.RESET_ALL}")
        
        if self.rate_limiter.rate_limit > 0:
            print(f"{Fore.YELLOW}[CONFIG]{Style.RESET_ALL} Rate Limit: {Fore.WHITE}{self.rate_limiter.rate_limit} req/s{Style.RESET_ALL}")
        
        if self.extensions:
            print(f"{Fore.YELLOW}[CONFIG]{Style.RESET_ALL} Extensions: {Fore.WHITE}{', '.join(self.extensions)}{Style.RESET_ALL}")
        
        if self.output_file:
            print(f"{Fore.YELLOW}[CONFIG]{Style.RESET_ALL} Output: {Fore.WHITE}{self.output_file}{Style.RESET_ALL}")
        
        print(f"{Fore.YELLOW}[CONFIG]{Style.RESET_ALL} Status Codes: {Fore.WHITE}{', '.join(map(str, self.status_codes))}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[CONFIG]{Style.RESET_ALL} SSL Verification: {Fore.WHITE}{'Enabled' if self.verify_ssl else 'Disabled'}{Style.RESET_ALL}")
        
        if self.proxy:
            print(f"{Fore.YELLOW}[CONFIG]{Style.RESET_ALL} Proxy: {Fore.WHITE}{self.proxy}{Style.RESET_ALL}")
        
        print()
    
    def _print_result(self, result):
        """Imprime un resultado encontrado con colores, encima de la barra de progreso."""
        status_code = result['status_code']
        url = result['url']
        size = result['content_length']
        time_ms = int(result['response_time'] * 1000)
        
        # Colorear según el código de estado
        if status_code == 200:
            status_color = Fore.GREEN
        elif status_code in [301, 302, 307]:
            status_color = Fore.YELLOW
        elif status_code in [401, 403]:
            status_color = Fore.RED
        else:
            status_color = Fore.CYAN
        
        result_line = (f"{Fore.GREEN}[FOUND]{Style.RESET_ALL} "
                      f"{status_color}{status_code}{Style.RESET_ALL} "
                      f"{Fore.WHITE}{url}{Style.RESET_ALL} "
                      f"({Fore.CYAN}{size}B{Style.RESET_ALL}, "
                      f"{Fore.MAGENTA}{time_ms}ms{Style.RESET_ALL})")
        
        # Usar el lock para imprimir de forma thread-safe
        with self.output_lock:
            if self.progress_bar:
                # Limpiar la línea actual de la barra de progreso
                self.progress_bar.clear()
                # Imprimir el resultado
                print(result_line)
                # Refrescar la barra de progreso
                self.progress_bar.refresh()
            else:
                print(result_line)
    
    def _print_info(self, message):
        """Imprime un mensaje informativo."""
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {message}")
    
    def _print_error(self, message):
        """Imprime un mensaje de error."""
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}")
    
    def _print_success(self, message):
        """Imprime un mensaje de éxito."""
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {message}")
    
    def _save_results(self):
        """Guarda los resultados en un archivo."""
        if not self.output_file or not self.found_urls:
            return
        
        try:
            with open(self.output_file, 'w', encoding='utf-8') as f:
                f.write(f"# PyDirb Results for {self.target_url}\n")
                f.write(f"# Generated at {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                for result in self.found_urls:
                    f.write(f"{result['status_code']} {result['url']} "
                           f"({result['content_length']}B, "
                           f"{int(result['response_time'] * 1000)}ms)\n")
            
            self._print_success(f"Resultados guardados en: {self.output_file}")
            
        except Exception as e:
            self._print_error(f"Error al guardar resultados: {e}")
    
    def _print_summary(self, elapsed_time):
        """Imprime un resumen del escaneo."""
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}RESUMEN DEL ESCANEO{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"URLs encontradas: {Fore.GREEN}{len(self.found_urls)}{Style.RESET_ALL}")
        print(f"Total de peticiones: {Fore.YELLOW}{self.total_requests}{Style.RESET_ALL}")
        print(f"Peticiones exitosas: {Fore.GREEN}{self.successful_requests}{Style.RESET_ALL}")
        print(f"Tiempo transcurrido: {Fore.MAGENTA}{elapsed_time:.2f}s{Style.RESET_ALL}")
        
        if self.total_requests > 0:
            rate = self.total_requests / elapsed_time
            print(f"Velocidad promedio: {Fore.CYAN}{rate:.2f} req/s{Style.RESET_ALL}")
    
    def _url_producer(self, words_generator, total_urls):
        """Hilo productor que genera URLs y las pone en la cola de forma controlada."""
        try:
            urls_generated = 0
            for url in self._generate_urls_generator(words_generator):
                # Bloquea si la cola está llena (control de memoria)
                self.url_queue.put(url, block=True)
                urls_generated += 1
                
                # Pequeña pausa para no saturar
                if urls_generated % 1000 == 0:
                    time.sleep(0.001)
                    
        except Exception as e:
            self._print_error(f"Error en productor de URLs: {e}")
        finally:
            # Señal de fin
            self.url_queue.put(None)
    
    def _url_consumer(self, executor, futures_dict):
            """Hilo consumidor que toma URLs de la cola y las procesa."""
            try:
                while True:
                    url = self.url_queue.get(block=True, timeout=30)
                    if url is None:  # Señal de fin
                        break
                    
                    # Enviar tarea al executor
                    future = executor.submit(self._process_url, url)
                    futures_dict[future] = url
                    
            except queue.Empty:
                pass  # Timeout normal
            except Exception as e:
                self._print_error(f"Error en consumidor de URLs: {e}")
        
    def _calculate_total_urls(self, word_count):
            """Calcula el total de URLs que se van a generar."""
            extensions_count = len(self.extensions) if self.extensions else 0
            return word_count + (word_count * extensions_count)
    
    def run(self):
        """Ejecuta el escaneo principal."""
        start_time = time.time()
        
        # Mostrar banner y configuración
        self._print_banner()
        self._print_config()
        
        # Cargar diccionario
        
        # Verificar conectividad inicial
        self._print_info(f"Verificando conectividad con {self.target_url}...")
        test_response = self._make_request(self.target_url)
        if test_response is None:
            self._print_error("No se pudo conectar con el objetivo")
            return
        
        self._print_success("Conectividad verificada. Iniciando escaneo...")
        print()
        
        # Contar palabras del diccionario (más eficiente)
        word_count = self._count_wordlist_lines()
        if word_count == 0:
            return
            
        total_urls = self._calculate_total_urls(word_count)
        self._print_info(f"Se van a probar {total_urls:,} URLs ({word_count:,} palabras)")
        
        # Generar palabras de forma lazy
        words_generator = self._load_wordlist_generator()
        
        # Ejecutar escaneo con memoria optimizada
        with tqdm(total=total_urls, desc="Escaneando", unit="urls", 
                  bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
                  position=0, leave=False, dynamic_ncols=True) as pbar:
            
            # Guardar referencia a la barra de progreso
            self.progress_bar = pbar
            
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures_dict = {}
                
                # Iniciar hilo productor de URLs
                producer_thread = threading.Thread(
                    target=self._url_producer, 
                    args=(words_generator, total_urls)
                )
                producer_thread.daemon = True
                producer_thread.start()
                
                # Iniciar hilo consumidor de URLs  
                consumer_thread = threading.Thread(
                    target=self._url_consumer,
                    args=(executor, futures_dict)
                )
                consumer_thread.daemon = True
                consumer_thread.start()
                
                # Procesar resultados conforme van llegando
                completed_count = 0
                while completed_count < total_urls or futures_dict:
                    # Procesar futuros completados
                    completed_futures = []
                    for future in list(futures_dict.keys()):
                        if future.done():
                            completed_futures.append(future)
                    
                    for future in completed_futures:
                        try:
                            result = future.result()
                            if result:
                                self.found_urls.append(result)
                                self._print_result(result)
                            
                            completed_count += 1
                            pbar.update(1)
                            
                            # Limpiar referencia
                            del futures_dict[future]
                            
                            # Garbage collection periódico para wordlists grandes
                            if completed_count % 1000 == 0:
                                gc.collect()
                                
                        except Exception as e:
                            completed_count += 1
                            pbar.update(1)
                            del futures_dict[future]
                    
                    # Pequeña pausa para no saturar la CPU
                    time.sleep(0.001)
                    
                    # Verificar si hemos terminado
                    if completed_count >= total_urls:
                        break
            
            # Limpiar la barra de progreso
            self.progress_bar = None
        
        # Limpiar la línea de la barra de progreso completamente
        print("\033[K", end="")  # Limpiar línea actual
        
        # Mostrar resumen
        elapsed_time = time.time() - start_time
        self._print_summary(elapsed_time)
        
        # Guardar resultados si se especificó
        self._save_results()


def validate_url(url):
    """Valida que la URL tenga un formato correcto."""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False

def parse_status_codes(status_codes_str):
    """Parsea los códigos de estado desde string a lista de enteros."""
    try:
        return [int(code.strip()) for code in status_codes_str.split(',')]
    except ValueError:
        raise argparse.ArgumentTypeError("Los códigos de estado deben ser números separados por comas")


def parse_extensions(extensions_str):
    """Parsea las extensiones desde string a lista."""
    return [ext.strip() for ext in extensions_str.split(',') if ext.strip()]


def main():
    """Función principal del programa."""
    parser = argparse.ArgumentParser(
        description="PyDirb - Herramienta profesional de Directory Bruteforce",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos de uso:
  %(prog)s http://example.com -w /usr/share/wordlists/dirb/common.txt
  %(prog)s https://target.com -w wordlist.txt -t 20 -r 50 --verify-ssl
  %(prog)s http://site.com -w dict.txt -e php,html,txt -o results.txt
  %(prog)s https://app.com -w list.txt -t 15 -s 200,301,403 -r 30 --user-agent "Custom Scanner"
  %(prog)s http://hidden-site.onion -w wordlist.txt --proxy socks5h://127.0.0.1:9050
  %(prog)s https://target.com -w dict.txt --proxy http://proxy.company.com:8080
  %(prog)s http://site.com -w directory-list-2.3-medium.txt -t 50 --max-memory 200
        """
    )
    
    # Argumentos obligatorios
    parser.add_argument('url', help='URL objetivo para escanear')
    parser.add_argument('-w', '--wordlist', required=True,
                       help='Ruta al archivo de diccionario')
    
    # Argumentos opcionales
    parser.add_argument('-t', '--threads', type=int, default=10,
                       help='Número de hilos a usar (default: 10)')
    parser.add_argument('-r', '--rate', type=int, default=0,
                       help='Límite de peticiones por segundo (0 = sin límite)')
    parser.add_argument('-e', '--ext', type=parse_extensions,
                       help='Extensiones a probar separadas por comas (ej: php,html,txt)')
    parser.add_argument('-o', '--output',
                       help='Archivo para guardar los resultados')
    parser.add_argument('-s', '--status-codes', type=parse_status_codes,
                       default='200,204,301,302,307,401,403',
                       help='Códigos de estado válidos separados por comas (default: 200,204,301,302,307,401,403)')
    parser.add_argument('--verify-ssl', action='store_true',
                       help='Habilitar verificación de certificados SSL (default: deshabilitado)')
    parser.add_argument('--user-agent',
                       default='PyDirb/1.0 (Directory Scanner)',
                       help='User-Agent personalizado para las peticiones')
    parser.add_argument('--proxy',
                       help='Proxy para usar en las peticiones (ej: socks5h://127.0.0.1:9050, http://proxy:8080)')
    parser.add_argument('--max-memory', type=int, default=100,
                       help='Límite de memoria en MB para buffer de URLs (default: 100)')
    
    args = parser.parse_args()
    
    # Validar URL
    if not validate_url(args.url):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} URL inválida: {args.url}")
        sys.exit(1)
    
    # Validar archivo de diccionario
    if not Path(args.wordlist).exists():
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} El archivo de diccionario no existe: {args.wordlist}")
        sys.exit(1)
    
    # Validar threads
    if args.threads < 1 or args.threads > 100:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} El número de hilos debe estar entre 1 y 100")
        sys.exit(1)
    
    # Validar rate limit
    if args.rate < 0:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} El rate limit no puede ser negativo")
        sys.exit(1)
    
    try:
        # Crear y ejecutar el escáner
        scanner = PyDirb(
            target_url=args.url,
            wordlist_path=args.wordlist,
            threads=args.threads,
            rate_limit=args.rate,
            extensions=args.ext,
            output_file=args.output,
            status_codes=args.status_codes,
            verify_ssl=args.verify_ssl,
            proxy=args.proxy
        )
        
        # Actualizar User-Agent si se especificó
        if args.user_agent:
            scanner._update_user_agent(args.user_agent)
        
        scanner.run()
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[INTERRUPTED]{Style.RESET_ALL} Escaneo interrumpido por el usuario")
        sys.exit(0)
    except Exception as e:
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} Error inesperado: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()