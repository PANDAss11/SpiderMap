from rich.console import Console
from rich.text import Text

console = Console() 
ASCII_HEADER = r"""
 (                                 *           (     
 )\ )            (               (  `          )\ )  
(()/(       (    )\ )   (   (    )\))(      ) (()/(  
 /(_))`  )  )\  (()/(  ))\  )(  ((_)()\  ( /(  /(_)) 
(_))  /(/( ((_)  ((_))/((_)(()\ (_()((_) )(_))(_))   
/ __|((_)_\ (_)  _| |(_))   ((_)|  \/  |((_)_ | _ \  
\__ \| '_ \)| |/ _` |/ -_) | '_|| |\/| |/ _` ||  _/  
|___/| .__/ |_|\__,_|\___| |_|  |_|  |_|\__,_||_|    
     |_|                                             
                                                    
  Powerful Subdomain & Active Finder
  Developed By: panda_big_money
"""

from rich.text import Text

colors = ["red", "orange1", "yellow", "bright_red", "dark_orange"]
text = Text()
for i, line in enumerate(ASCII_HEADER.splitlines(True)):
    color = colors[i % len(colors)]
    text.append(line, style=f"{color} bold")
console.print(text)


import concurrent.futures
import json
import os
import re
import sys
import time

try:
    import requests
    import dns.resolver
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
except Exception:
    print("Install dependencies: pip3 install requests dnspython rich")
    sys.exit(1)

DEFAULT_WORDLIST = "wordlist.txt"
OUTPUT_FILE = "found_subdomains.txt"
ACTIVE_OUTPUT = "active_subdomains.txt"

console = Console()

def query_crtsh(domain):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        r = requests.get(url, timeout=15)
        if r.status_code != 200:
            return set()
        data = r.json()
        names = set()
        for item in data:
            name = item.get('name_value') or item.get('common_name')
            if not name:
                continue
            for n in name.split('\n'):
                n = n.strip().lower()
                if n.endswith('.' + domain) or n == domain:
                    n = n.lstrip('*.')
                    names.add(n)
        return names
    except Exception:
        return set()

def read_wordlist(path):
    if not os.path.exists(path):
        return []
    with open(path, 'r', errors='ignore') as fh:
        return [w.strip() for w in fh if w.strip()]

def build_permutations(names):
    perms = set()
    tokens = ['www', 'dev', 'test', 'stage', 'api', 'mail', 'admin']
    for n in names:
        base = n.split('.')[0]
        for t in tokens:
            perms.add(f"{t}.{n}")
            parts = n.split('.')
            if len(parts) > 1:
                perms.add(f"{base}-{t}.{'.'.join(parts[1:])}")
                perms.add(f"{t}{base}.{'.'.join(parts[1:])}")
    return perms

def bruteforce(domain, words, threads=50):
    names = set()
    def make(w):
        return f"{w}.{domain}"
    with concurrent.futures.ThreadPoolExecutor(max_workers=min(threads,200)) as exe:
        futures = [exe.submit(make, w) for w in words]
        for fut in concurrent.futures.as_completed(futures):
            names.add(fut.result())
    return names

def resolve(host):
    ips = set()
    try:
        answers = dns.resolver.resolve(host, 'A', lifetime=5)
        for r in answers:
            ips.add(r.to_text())
    except Exception:
        pass
    try:
        answers = dns.resolver.resolve(host, 'AAAA', lifetime=5)
        for r in answers:
            ips.add(r.to_text())
    except Exception:
        pass
    return list(ips)

def wildcard_check(domain):
    rand = f"{int(time.time())}.{domain}"
    try:
        a = resolve(rand)
        return bool(a)
    except Exception:
        return False

def http_probe(host, timeout=6):
    for proto in ('https://', 'http://'):
        url = proto + host
        try:
            r = requests.get(url, timeout=timeout, allow_redirects=True)
            title = ''
            m = re.search(r'<title>(.*?)</title>', r.text, re.IGNORECASE | re.DOTALL)
            if m:
                title = m.group(1).strip()
            return r.status_code, url, title
        except requests.exceptions.SSLError:
            continue
        except Exception:
            continue
    return None, None, None

def check_host(host):
    ips = resolve(host)
    status, url, title = http_probe(host)
    return {'host': host, 'ips': ips, 'http_status': status, 'http_url': url, 'title': title}

def scan_all(subs, threads=50):
    results = []
    active = []
    total = len(subs)
    with Progress(SpinnerColumn(), TextColumn("Scanning: {task.fields[host]}"), BarColumn(), TimeElapsedColumn()) as progress:
        task = progress.add_task("scan", total=total, host="-")
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as exe:
            futures = {exe.submit(check_host, s): s for s in subs}
            for fut in concurrent.futures.as_completed(futures):
                try:
                    r = fut.result()
                    if r['ips'] or r['http_status']:
                        results.append(r)
                        if r['ips'] and r['http_status']:
                            active.append(r)
                    progress.update(task, advance=1, host=r['host'])
                except Exception:
                    progress.update(task, advance=1)
    return results, active

def save(results, path=OUTPUT_FILE):
    with open(path, 'w') as fh:
        for r in results:
            fh.write(json.dumps(r) + '\n')

def prompt_input():
    domain = console.input('[bold cyan]Enter target domain (example.com):[/] ')
    wl = console.input('[bold cyan]Wordlist path (press enter for wordlist.txt):[/] ')
    th = console.input('[bold cyan]Threads (press enter for 50):[/] ')
    use_crt = console.input('[bold cyan]Use crt.sh? (Y/n):[/] ')
    use_brute = console.input('[bold cyan]Do brute force? (Y/n):[/] ')
    domain = domain.strip().lower()
    wl = wl.strip() or DEFAULT_WORDLIST
    th = int(th.strip()) if th.strip().isdigit() else 50
    use_crt = use_crt.strip().lower() != 'n'
    use_brute = use_brute.strip().lower() != 'n'


    if use_brute and not os.path.exists(wl):
        console.print(f"[bold red]Wordlist not found at: {wl}[/]")
        choice = console.input('[bold cyan]Choose: (G)enerate a small built-in list / (D)ownload example / (S)kip brute force [G/d/s]:[/] ')
        choice = choice.strip().lower() or 'g'
        if choice == 's':
            use_brute = False
            wl = ''
        elif choice == 'd':
            
            console.print('[bold yellow]Attempting to download sample wordlist...[/]')
            try:
                url = 'https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt'
                r = requests.get(url, timeout=10)
                if r.status_code == 200 and r.text:
                    with open(DEFAULT_WORDLIST, 'w') as fh:
                        fh.write(r.text)
                    wl = DEFAULT_WORDLIST
                    console.print(f'[bold green]Downloaded sample wordlist to {DEFAULT_WORDLIST}[/]')
                else:
                    console.print('[bold red]Download failed, falling back to built-in list[/]')
                    choice = 'g'
            except Exception:
                console.print('[bold red]Download failed, falling back to built-in list[/]')
                choice = 'g'
        if choice == 'g':
           
            built_in = [
                'www', 'mail', 'smtp', 'api', 'dev', 'test', 'stage', 'admin', 'portal', 'secure',
                'ftp', 'webmail', 'ns1', 'ns2', 'blog', 'shop', 'vpn', 'beta', 'm', 'cdn'
            ]
            with open(DEFAULT_WORDLIST, 'w') as fh:
                fh.write(''.join(built_in))
            wl = DEFAULT_WORDLIST
            console.print(f'[bold green]Created small built-in wordlist at {DEFAULT_WORDLIST}[/]')

    return domain, wl, th, use_crt, use_brute

def display_results(all_found, active_found):
    table_all = Table(title=f"All discovered subdomains ({len(all_found)})", show_lines=True)
    table_all.add_column("Host", style="magenta")
    table_all.add_column("IPs", style="green")
    table_all.add_column("HTTP", style="yellow")
    table_all.add_column("Title", style="cyan")
    for r in all_found:
        table_all.add_row(r['host'], ",".join(r['ips']) or '-', str(r['http_status'] or '-'), r['title'] or '-')

    table_active = Table(title=f"Active subdomains ({len(active_found)})", show_lines=True)
    table_active.add_column("Host", style="bold magenta")
    table_active.add_column("IPs", style="bold green")
    table_active.add_column("HTTP URL", style="bold yellow")
    for r in active_found:
        table_active.add_row(r['host'], ",".join(r['ips']) or '-', r['http_url'] or '-')

    console.print(Panel(table_all, border_style="bright_blue"))
    console.print(Panel(table_active, border_style="bright_green"))

def main():
    domain, wordlist_path, threads, use_crt, use_brute = prompt_input()
    pool = set()
    if use_crt:
        crt = query_crtsh(domain)
        pool.update(crt)
    words = read_wordlist(wordlist_path)
    if use_brute and words:
        brute = bruteforce(domain, words, threads=threads)
        pool.update(brute)
    pool.add(domain)
    pool.update(build_permutations(pool))
    pool = set([s.lstrip('*.') for s in pool if s])
    if wildcard_check(domain):
        console.print('[bold red]Wildcard DNS detected; filtered results may be noisy[/]')
    subs = sorted(pool)
    console.print(f'[bold yellow]Total to check: {len(subs)}[/]')
    results, active = scan_all(subs, threads=threads)
    save(results, OUTPUT_FILE)
    save(active, ACTIVE_OUTPUT)
    console.print(f'[bold green]Saved {len(results)} total results to {OUTPUT_FILE}[/]')
    console.print(f'[bold green]Saved {len(active)} active results to {ACTIVE_OUTPUT}[/]')
    display_results(results, active)

if __name__ == '__main__':
    main()