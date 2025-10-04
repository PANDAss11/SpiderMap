# SpiderMap - Powerful Subdomain & Active Finder


SpiderMap is a powerful Python tool designed to discover and check subdomains of a target domain. It integrates **crt.sh enumeration**, **brute-force scanning**, and **active HTTP probing** to provide a complete picture of your target's subdomain landscape.

## Features

* Fetch subdomains from [crt.sh](https://crt.sh/)
* Brute-force subdomain discovery using a wordlist
* Wildcard DNS detection
* Resolve A and AAAA records
* HTTP/HTTPS probing with title detection
* Colorful and clear terminal output using [Rich](https://rich.readthedocs.io/)
* Active subdomains displayed separately
* Save results to `found_subdomains.txt` and `active_subdomains.txt`

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/SpiderMap.git
cd SpiderMap
```

2. Install dependencies:

```bash
pip install -r requirements.txt
# or individually
pip install requests dnspython rich
```

3. Ensure you have a wordlist (optional for brute-force). If missing, SpiderMap can generate a small built-in list.

## Usage

Run the tool:

```bash
python spidermap.py
```

You will be prompted for:

* Target domain (e.g., example.com)
* Wordlist path (default: `wordlist.txt`)
* Threads (default: 50)
* Use crt.sh? (Y/n)
* Do brute force? (Y/n)

SpiderMap will display all discovered subdomains and highlight active ones in a separate table.

## Files

* `found_subdomains.txt` - All discovered subdomains with IPs and HTTP status.
* `active_subdomains.txt` - Only subdomains that responded to HTTP requests.
* `wordlist.txt` - Optional wordlist for brute-force scanning.

## Notes

* Requires Python 3.7+
* Supports Windows, Linux, macOS terminals
* Make sure your terminal supports ANSI colors for the colored ASCII header.

## License

This project is developed by **panda_big_money** and is open for educational and personal use.

---

**Disclaimer:** Use SpiderMap only on domains you own or have explicit permission to test.
