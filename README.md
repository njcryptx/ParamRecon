# ParamRecon - Advanced HTTP Parameter Finder

ParamRecon is an advanced HTTP parameter discovery tool designed for penetration testers and security researchers. It helps identify potential GET and POST parameters on a target URL, making it useful for bug bounty hunting and security assessments.

## Features
- Fast multi-threaded scanning
- Built-in extensive wordlist (1000+ parameters)
- Supports custom headers, cookies, and proxy
- Detects parameter reflection for XSS, SQLi, and Open Redirect vulnerabilities
- Fuzzing mode for bypassing Web Application Firewalls (WAF)
- Multiple output formats: JSON, CSV, and TXT

## Installation

### Prerequisites
Ensure you have Python installed (version 3.x required). Install necessary dependencies using:
```bash
pip install -r requirements.txt
```

### Required Dependencies
The tool requires the following Python libraries:
```bash
pip install argparse requests ratelimit
```

## Usage

### Basic Scan
```bash
python paramrecon.py <URL>
```
Example:
```bash
python paramrecon.py https://example.com
```

### Using Custom Wordlist
```bash
python paramrecon.py <URL> -w custom_wordlist.txt
```

### Setting HTTP Method (GET/POST)
```bash
python paramrecon.py <URL> -m POST
```

### Adding Custom Headers
```bash
python paramrecon.py <URL> -H '{"User-Agent": "Mozilla/5.0"}'
```

### Enabling Fuzzing Mode
```bash
python paramrecon.py <URL> -f
```

### Output Options
Save results in different formats:
- JSON: `-o json`
- CSV: `-o csv`
- TXT: `-o txt`

Example:
```bash
python paramrecon.py <URL> -o csv
```

## Example Output
```
[+] Found parameter: page
[+] Found parameter: search
[+] Found parameter: user
[+] Results saved to discovered_params.json
```

## Contributing
Pull requests are welcome! If you find a bug or want to add a feature, feel free to open an issue.

## License
This project is licensed under the MIT License.

## Contact
For any issues or suggestions, reach out via GitHub Issues.

Happy Hacking! 🚀

