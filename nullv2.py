#!/usr/bin/env python3
import sys
import time
import os
import json
import hashlib
import uuid
import requests
import base64
import random
import string
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from colorama import init, Fore, Style

init(autoreset=True)

# Encryption settings
TOKEN_PASSPHRASE = "f0a5baf4-f90b-4800-a407-eb5065382113"
WEBHOOK_PASSPHRASE = "fdfac521-be53-4ed5-b7a0-47606a2f3821"

# Encrypted tokens
ENCRYPTED_GITHUB_TOKEN = "U2FsdGVkX1+EsNr+p0PWwWMW3udxhDXtt6WfIUaTVivHMUcE6wb4CPWd7spuy3moFuiadjsEQGPzojlv30mjc2sPklc8o4FLKqP/xehTeShOgn7LbTfVoiTIy5Sd7F1FKfjcBUSaOb0Zh6jk3JMYgw=="
ENCRYPTED_WEBHOOK = "U2FsdGVkX1+Nw4U/zl83/gKNEByPtf6hHZCyga+N6cKvQZNTQgo9fp4UjeajxHOySDCuZhv6PbgzS+VtCTMzE6ULKXqHChvUSVKiQRxjINzWrVIyWBMs2B3QwUZYflKrEJYj25kQ4wCcLaRIMJUmuoKpmpmKy+5oLz5Bi9FjYzOv8ftNm7Ye41t6Sy87Prwz"

# GitHub repository information
REPO_OWNER = "egirlhunt"
REPO_NAME = "nulllkeys"
FILE_PATH = "keys.json"

# GitHub API URL
GITHUB_API_URL = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH}"

# Color themes with gradient ranges
COLOR_THEMES = {
    "1": {"name": "Red", "dark": 124, "medium": 160, "light": 196, "gradient_range": [124, 160, 196]},
    "2": {"name": "Blue", "dark": 18, "medium": 33, "light": 69, "gradient_range": [18, 33, 69, 75, 81]},
    "3": {"name": "Green", "dark": 22, "medium": 46, "light": 82, "gradient_range": [22, 46, 82, 118, 154]},
    "4": {"name": "Purple", "dark": 54, "medium": 93, "light": 129, "gradient_range": [54, 93, 129, 165, 201]},
    "5": {"name": "Cyan", "dark": 23, "medium": 44, "light": 51, "gradient_range": [23, 44, 51, 87, 123]},
    "6": {"name": "Yellow", "dark": 94, "medium": 178, "light": 226, "gradient_range": [94, 136, 178, 220, 226]},
    "7": {"name": "White", "dark": 7, "medium": 15, "light": 231, "gradient_range": [7, 15, 231]},
    "8": {"name": "Orange", "dark": 130, "medium": 166, "light": 202, "gradient_range": [130, 166, 202, 208, 214]},
    "9": {"name": "Pink", "dark": 125, "medium": 162, "light": 219, "gradient_range": [125, 162, 199, 205, 219]},
    "10": {"name": "Rainbow", "rainbow": True, "gradient_range": list(range(196, 51, -1))}
}

# Current theme (default to red)
current_theme = COLOR_THEMES["1"]
current_gradient_colors = [124, 160, 196]

def evp_bytes_to_key(password, salt, key_len=32, iv_len=16):
    """OpenSSL EVP_BytesToKey compatible key derivation"""
    d = d_i = b''
    while len(d) < key_len + iv_len:
        d_i = hashlib.md5(d_i + password + salt).digest()
        d += d_i
    return d[:key_len], d[key_len:key_len+iv_len]

def decrypt_aes_openssl(encrypted_text, passphrase):
    """Decrypt AES-256-CBC encrypted text (OpenSSL compatible)"""
    try:
        # Decode base64
        encrypted_data = base64.b64decode(encrypted_text)
        
        # Check for "Salted__" prefix
        if encrypted_data[:8] != b'Salted__':
            return ""
        
        # Extract salt (8 bytes after "Salted__")
        salt = encrypted_data[8:16]
        ciphertext = encrypted_data[16:]
        
        # Derive key and IV using OpenSSL's EVP_BytesToKey
        password = passphrase.encode('utf-8')
        key, iv = evp_bytes_to_key(password, salt, 32, 16)
        
        # Decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        
        # Remove PKCS7 padding
        plaintext = unpad(decrypted, AES.block_size)
        
        return plaintext.decode('utf-8')
        
    except Exception:
        return ""

def get_github_token():
    """Get decrypted GitHub token"""
    token = decrypt_aes_openssl(ENCRYPTED_GITHUB_TOKEN, TOKEN_PASSPHRASE)
    return token

def get_webhook_url():
    """Get decrypted webhook URL"""
    return decrypt_aes_openssl(ENCRYPTED_WEBHOOK, WEBHOOK_PASSPHRASE)

def get_hwid():
    """Generate a unique hardware ID"""
    try:
        hwid_parts = []
        
        # Get MAC address
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                       for elements in range(0, 8*6, 8)][::-1])
        hwid_parts.append(mac)
        
        # Get machine ID if available
        if os.name == 'posix':
            try:
                with open('/etc/machine-id', 'r') as f:
                    hwid_parts.append(f.read().strip())
            except:
                pass
        
        # Create hash from all parts
        hwid_string = '-'.join(hwid_parts)
        return hashlib.sha256(hwid_string.encode()).hexdigest()[:32]
        
    except Exception as e:
        return str(uuid.getnode())

def generate_random_id():
    """Generate a random 16-character ID"""
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(characters) for _ in range(16))

def save_id_to_file(user_id, license_key):
    """Save ID to text file with warning"""
    warning_text = """⚠️ WARNING: NEVER SHARE THIS ID ⚠️

SHARING THIS COULD LEAD TO YOUR LICENSE KEY GETTING REMOVED OR STOLEN

ANYONE ELSE THAN @uekv ON DISCORD ASKING FOR THIS ID IS A SCAMMER/FAKER

YOUR ID: {user_id}
YOUR LICENSE KEY: {license_key}

This ID is your proof of ownership.
If you lose it, use the "Generate ID" option in the tool.
""".format(user_id=user_id, license_key=license_key)
    
    with open("ID.txt", "w") as f:
        f.write(warning_text)
    
    print(f"{get_color('medium')}[+]{Style.RESET_ALL} {Fore.WHITE}ID saved to ID.txt{Style.RESET_ALL}")
    print(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Keep this file safe! Never share it!{Style.RESET_ALL}")

def get_color(intensity="medium"):
    """Get color based on current theme and intensity"""
    if current_theme.get("rainbow"):
        # For rainbow, cycle through colors based on line number
        return "\033[38;5;{}m".format(random.choice(current_theme["gradient_range"]))
    
    if intensity == "dark":
        return "\033[38;5;{}m".format(current_theme["dark"])
    elif intensity == "light":
        return "\033[38;5;{}m".format(current_theme["light"])
    else:
        return "\033[38;5;{}m".format(current_theme["medium"])

def get_gradient_color(line_num, total_lines):
    """Get gradient color for a specific line"""
    if current_theme.get("rainbow"):
        # Rainbow: cycle through the full range
        color_index = line_num % len(current_theme["gradient_range"])
        return "\033[38;5;{}m".format(current_theme["gradient_range"][color_index])
    else:
        # Normal gradient: dark to light
        gradient_colors = current_theme["gradient_range"]
        color_index = min(line_num * len(gradient_colors) // total_lines, len(gradient_colors) - 1)
        return "\033[38;5;{}m".format(gradient_colors[color_index])

def center_text(text, width=80):
    """Center text within given width"""
    return text.center(width)

def print_centered(text, color_func=None, width=80):
    """Print centered text with optional color"""
    centered = text.center(width)
    if color_func:
        print(color_func + centered + Style.RESET_ALL)
    else:
        print(centered)

def fetch_license_data():
    """Fetch and parse license data from private GitHub repository"""
    try:
        github_token = get_github_token()
        if not github_token:
            print(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Failed to decrypt GitHub token{Style.RESET_ALL}")
            return []
        
        print(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Connecting to private database...{Style.RESET_ALL}")
        
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        response = requests.get(GITHUB_API_URL, headers=headers, timeout=10)
        
        if response.status_code == 200:
            file_info = response.json()
            content = base64.b64decode(file_info["content"]).decode('utf-8')
            licenses = json.loads(content)
            print(f"{get_color('medium')}[+]{Style.RESET_ALL} {Fore.GREEN}Private database connected successfully{Style.RESET_ALL}")
            print(f"{get_color('medium')}[•]{Style.RESET_ALL} {Fore.WHITE}Found {len(licenses)} licenses in database{Style.RESET_ALL}")
            return licenses
        elif response.status_code == 404:
            print(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}File not found{Style.RESET_ALL}")
        elif response.status_code == 401:
            print(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Authentication failed{Style.RESET_ALL}")
        elif response.status_code == 403:
            print(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Access forbidden{Style.RESET_ALL}")
        else:
            print(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Database connection failed: {response.status_code}{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Database error: {e}{Style.RESET_ALL}")
    
    return []

def update_license_data(license_key, new_hwid, new_id=""):
    """Update license data in private GitHub repository"""
    try:
        github_token = get_github_token()
        if not github_token:
            print(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Failed to decrypt GitHub token{Style.RESET_ALL}")
            return False
        
        # Get current file info
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        response = requests.get(GITHUB_API_URL, headers=headers, timeout=10)
        if response.status_code != 200:
            print(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Failed to access database: {response.status_code}{Style.RESET_ALL}")
            return False
        
        file_info = response.json()
        current_sha = file_info["sha"]
        current_content = base64.b64decode(file_info["content"]).decode('utf-8')
        
        # Parse and update the JSON
        licenses = json.loads(current_content)
        updated = False
        
        for license_entry in licenses:
            if license_entry.get("Licensekey") == license_key:
                license_entry["hwid"] = new_hwid
                if new_id and not license_entry.get("id"):
                    license_entry["id"] = new_id
                updated = True
                break
        
        if not updated:
            print(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}License not found in database{Style.RESET_ALL}")
            return False
        
        # Update file on GitHub
        update_data = {
            "message": f"Update HWID/ID for {license_key[:8]}...",
            "content": base64.b64encode(json.dumps(licenses, indent=2).encode()).decode(),
            "sha": current_sha
        }
        
        update_response = requests.put(GITHUB_API_URL, headers=headers, json=update_data, timeout=10)
        
        if update_response.status_code in [200, 201]:
            print(f"{get_color('medium')}[+]{Style.RESET_ALL} {Fore.GREEN}Private database updated successfully{Style.RESET_ALL}")
            return True
        else:
            print(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Database update failed: {update_response.status_code}{Style.RESET_ALL}")
            return False
            
    except Exception as e:
        print(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Update error: {e}{Style.RESET_ALL}")
        return False

def send_webhook(license_key, hwid, user_id=""):
    """Send registration to webhook"""
    try:
        webhook_url = get_webhook_url()
        if not webhook_url:
            return
        
        fields = [
            {"name": "License key", "value": f"`{license_key}`", "inline": True},
            {"name": "HWID", "value": f"`{hwid}`", "inline": True}
        ]
        
        if user_id:
            fields.append({"name": "User ID", "value": f"`{user_id}`", "inline": True})
        
        payload = {
            "embeds": [{
                "title": "NEW REGISTRATION",
                "color": 16711680,
                "fields": fields,
                "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())
            }]
        }
        response = requests.post(webhook_url, json=payload, timeout=5)
        if response.status_code in [200, 204]:
            print(f"{get_color('medium')}[+]{Style.RESET_ALL} {Fore.GREEN}Registration logged{Style.RESET_ALL}")
    except Exception:
        pass

def clear_screen_preserve_header():
    """Clear screen but preserve the header"""
    os.system('cls' if os.name == 'nt' else 'clear')
    display_gradient_ascii_header_only()

def display_gradient_ascii_header_only():
    """Display only the header (ASCII art and made by text)"""
    ascii_graphic = [
        "⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
        "⠀⠀⠀⠀⠀⡀⣰⡿⠛⠛⠿⢶⣦⣀⠀⢀⣀⣀⣀⣀⣠⡾⠋⠀⠀⠹⣷⣄⣤⣶⡶⠿⠿⣷⡄⠀⠀⠀⠀⠀",
        "⠀⠀⠀⠀⠀⢰⣿⠁⠀⠀⠀⠀⠈⠙⠛⠛⠋⠉⠉⢹⡟⠁⠀⠀⣀⣀⠘⣿⠉⠀⠀⠀⠀⠘⣿⠀⠀⠀⠀⠀",
        "⠀⠀⠀⠀⠀⢸⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠁⠀⠀⣾⡋⣽⠿⠛⠿⢶⣤⣤⣤⣤⣿⠀⠀⠀⠀⠀",
        "⠀⠀⠀⠀⠀⢸⣿⡴⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣄⡀⠀⢈⣻⡏⠀⠀⠀⠀⣿⣀⠀⠈⠙⣷⠀⠀⠀⠀",
        "⠀⠀⠀⠀⠀⣰⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠛⠛⠛⠙⢷⣄⣀⣀⣼⣏⣿⠀⠀⢀⣿⠀⠀⠀⠀",
        "⠀⠀⠀⠀⢸⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠙⣿⡉⠉⠁⢀⣠⣿⡇⠀⠀⠀⠀",
        "⠀⠀⠀⠀⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠛⠗⠾⠟⠋⢹⣷⠀⠀⠀⠀",
        "⢀⣤⣤⣤⣿⣤⣄⠀⠀⠀⠴⠚⠲⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣠⣶⡆⠀⠀⠀⠀⢀⣈⣿⣀⣀⡀⠀",
        "⠀⠀⠀⠈⣿⣠⣾⠟⠛⢷⡄⠀⠀⠀⠀⠀⠀⠀⡤⠶⢦⡀⠀⠀⠀⠀⠹⠯⠃⠀⠀⠀⠈⠉⢩⡿⠉⠉⠉⠁",
        "⠀⠀⣤⡶⠿⣿⣇⠀⠀⠸⣷⠀⠀⠀⠀⠀⠀⠀⠓⠶⠞⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢤⣼⣯⣀⣀⠀⠀",
        "⠀⢰⣯⠀⠀⠈⠻⠀⠀⠀⣿⣶⣤⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⡿⠁⠉⠉⠁⠀",
        "⠀⠀⠙⣷⣄⠀⠀⠀⠀⠀⢀⣀⣀⠙⢿⣆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢈⣿⡿⢷⣄⡀⠀⠀⠀",
        "⠀⠀⠀⠈⠙⣷⠀⠀⠀⣴⠟⠉⠉⠀⠀⣿⣀⣀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣠⣤⣾⠟⠉⠀⠀⠈⠉⠀⠀⠀",
        "⠀⠀⠀⠀⠰⣿⠀⠀⠀⠙⢧⣤⡶⠟⢀⣿⠛⢟⡟⡯⠽⢶⡶⠾⢿⣻⣏⣹⡏⣁⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀",
        "⠀⠀⠀⠀⠀⠹⣷⣄⠀⠀⠀⠀⠀⣠⣾⠏⠀⠀⠙⠛⠛⠋⠀⠀⢀⣽⠟⠛⠖⠛⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
        "⠀⠀⠀⠀⠀⠀⠀⠙⠻⠷⠶⠿⠟⠋⠹⣷⣤⣀⡀⠄⣡⣀⣠⣴⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
        "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠳⣍⣉⣻⣏⣉⣡⠞⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
        "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"
    ]
    
    ascii_text = [
        " ███▄    █  █    ██  ██▓     ██▓    ",
        " ██ ▀█   █  ██  ▓██▒▓██▒    ▓██▒    ",
        "▓██  ▀█ ██▒▓██  ▒██░▒██░    ▒██░    ",
        "▓██▒  ▐▌██▒▓▓█  ░██░▒██░    ▒██░    ",
        "▒██░   ▓██░▒▒█████▓ ░██████▒░██████▒",
        "░ ▒░   ▒ ▒ ░▒▓▒ ▒ ▒ ░ ▒░▓  ░░ ▒░▓  ░",
        "░ ░░   ░ ▒░░░▒░ ░ ░ ░ ░ ▒  ░░ ░ ▒  ░",
        "   ░   ░ ░  ░░░ ░ ░   ░ ░     ░ ░   ",
        "         ░    ░         ░  ░    ░  ░",
        "                                    "
    ]
    
    # Display graphic art with gradient
    for i, line in enumerate(ascii_graphic):
        color = get_gradient_color(i, len(ascii_graphic))
        print_centered(line, lambda: color)
    
    print("\n")
    
    # Display text art with gradient
    for i, line in enumerate(ascii_text):
        color = get_gradient_color(i + len(ascii_graphic), len(ascii_graphic) + len(ascii_text))
        print_centered(line, lambda: color)
    
    print("\n")
    
    # Add "made by @uekv on discord" with gradient
    made_by_text = "made by @uekv on discord"
    color = get_gradient_color(len(ascii_graphic) + len(ascii_text), len(ascii_graphic) + len(ascii_text) + 2)
    print_centered(made_by_text, lambda: color)
    
    # Gradient line
    gradient_line = "─" * 50
    print_centered(gradient_line, lambda: get_color("medium"))

def display_gradient_ascii():
    """Full display with license prompt"""
    display_gradient_ascii_header_only()
    print_centered(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Enter License Key > {Style.RESET_ALL}", width=80)

def display_color_selection():
    """Display color selection menu"""
    clear_screen_preserve_header()
    
    print_centered(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Color Selection Menu{Style.RESET_ALL}", width=80)
    print_centered(f"{get_color('medium')}══════════════════════════════{Style.RESET_ALL}", width=80)
    print()
    
    # Display colors in centered format
    colors_per_row = 2
    color_keys = list(COLOR_THEMES.keys())
    
    for i in range(0, len(color_keys), colors_per_row):
        row_text = ""
        for j in range(colors_per_row):
            if i + j < len(color_keys):
                key = color_keys[i + j]
                theme = COLOR_THEMES[key]
                color_code = f"\033[38;5;{theme['medium']}m"
                if theme.get("rainbow"):
                    color_code = "\033[38;5;196m"  # Red for rainbow label
                option = f"{color_code}[{key}]{Style.RESET_ALL}{Fore.WHITE} {theme['name']}"
                row_text += option.ljust(30)
        
        print_centered(row_text, width=80)
        if i + colors_per_row < len(color_keys):
            print_centered(f"{get_color('dark')}─{Style.RESET_ALL}", width=80)
    
    print()
    print_centered(f"{get_color('medium')}────────────────────────────────────{Style.RESET_ALL}", width=80)
    print_centered(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Select Color > {Style.RESET_ALL}", width=80)
    
    return input(" " * 35)  # Centered input

def display_options_grid():
    """Display options in centered format without boxes"""
    clear_screen_preserve_header()
    
    print_centered(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Main Menu - Welcome!{Style.RESET_ALL}", width=80)
    print_centered(f"{get_color('medium')}══════════════════════════════{Style.RESET_ALL}", width=80)
    print()
    
    options = [
        f"{get_color('light')}[1]{Style.RESET_ALL} Change Color",
        f"{get_color('light')}[2]{Style.RESET_ALL} Generate ID", 
        f"{get_color('light')}[3]{Style.RESET_ALL} Exit"
    ]
    
    # Display each option centered with gradient
    for i, option in enumerate(options):
        color = get_gradient_color(i, len(options))
        print_centered(option, lambda c=color: c)
        if i < len(options) - 1:
            print_centered(f"{get_color('dark')}─{Style.RESET_ALL}", width=80)
    
    print()
    print_centered(f"{get_color('medium')}────────────────────────────────────{Style.RESET_ALL}", width=80)
    print_centered(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Select Option > {Style.RESET_ALL}", width=80)
    
    return input(" " * 35)  # Centered input

def validate_license_key():
    """Validate license key against private GitHub database"""
    user_key = input().strip()
    
    if not user_key:
        print_centered(f"\n{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}No license key entered!{Style.RESET_ALL}", width=80)
        return False, ""
    
    print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Checking private database...{Style.RESET_ALL}", width=80)
    time.sleep(1)
    
    try:
        # Fetch license data from private GitHub database
        licenses = fetch_license_data()
        
        if not licenses:
            print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Private database connection failed{Style.RESET_ALL}", width=80)
            return False, ""
        
        # Find the license key
        license_found = False
        current_hwid = get_hwid()
        user_id = ""
        
        for license_entry in licenses:
            if license_entry.get("Licensekey") == user_key:
                license_found = True
                stored_hwid = license_entry.get("hwid", "").strip()
                user_id = license_entry.get("id", "").strip()
                
                if not stored_hwid:
                    # First time activation
                    print_centered(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}New activation detected{Style.RESET_ALL}", width=80)
                    
                    # Generate ID if not exists
                    if not user_id:
                        user_id = generate_random_id()
                        print_centered(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}Generated User ID: {user_id}{Style.RESET_ALL}", width=80)
                        save_id_to_file(user_id, user_key)
                    
                    # Send webhook notification
                    send_webhook(user_key, current_hwid, user_id)
                    
                    # Update GitHub database with HWID and ID
                    print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Updating private database...{Style.RESET_ALL}", width=80)
                    if update_license_data(user_key, current_hwid, user_id):
                        print_centered(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}License activated!{Style.RESET_ALL}", width=80)
                        time.sleep(2)
                        return True, user_key
                    else:
                        print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Database update failed{Style.RESET_ALL}", width=80)
                        return False, ""
                else:
                    # Check HWID match
                    if stored_hwid == current_hwid:
                        print_centered(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}Hardware verified{Style.RESET_ALL}", width=80)
                        if user_id and not os.path.exists("ID.txt"):
                            save_id_to_file(user_id, user_key)
                        time.sleep(1)
                        return True, user_key
                    else:
                        print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Hardware mismatch!{Style.RESET_ALL}", width=80)
                        print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Your HWID: {current_hwid[:16]}...{Style.RESET_ALL}", width=80)
                        print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Database HWID: {stored_hwid[:16]}...{Style.RESET_ALL}", width=80)
                        print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}If this is a mistake, DM @uekv{Style.RESET_ALL}", width=80)
                        
                        for i in range(10, 0, -1):
                            print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Closing in {i}...{Style.RESET_ALL}", width=80)
                            time.sleep(1)
                        return False, ""
        
        if not license_found:
            print_centered(f"\n{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}License not found in private database!{Style.RESET_ALL}", width=80)
            print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Closing in 3 seconds...{Style.RESET_ALL}", width=80)
            
            for i in range(3, 0, -1):
                print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Closing in {i}...{Style.RESET_ALL}", width=80)
                time.sleep(1)
            
            return False, ""
            
    except Exception as e:
        print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Database error: {e}{Style.RESET_ALL}", width=80)
        return False, ""
    
    return False, ""

def main():
    global current_theme, current_gradient_colors
    
    os.system('cls' if os.name == 'nt' else 'clear')
    display_gradient_ascii()
    
    valid_license, license_key = validate_license_key()
    
    if not valid_license:
        sys.exit(1)
    
    # Main menu loop
    while True:
        choice = display_options_grid()
        
        clear_screen_preserve_header()
        
        if choice == "1":
            # Change color
            color_choice = display_color_selection()
            if color_choice in COLOR_THEMES:
                current_theme = COLOR_THEMES[color_choice]
                current_gradient_colors = current_theme["gradient_range"]
                print_centered(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Color changed to {current_theme['name']}{Style.RESET_ALL}", width=80)
            else:
                print_centered(f"\n{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Invalid color choice{Style.RESET_ALL}", width=80)
            print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}", width=80)
            input(" " * 35)
            
        elif choice == "2":
            # Generate ID
            print_centered(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}Generating new ID...{Style.RESET_ALL}", width=80)
            
            # Check if license is still valid
            licenses = fetch_license_data()
            user_id = ""
            
            for license_entry in licenses:
                if license_entry.get("Licensekey") == license_key:
                    user_id = license_entry.get("id", "").strip()
                    break
            
            if not user_id:
                user_id = generate_random_id()
                # Update database with new ID
                update_license_data(license_key, get_hwid(), user_id)
            
            save_id_to_file(user_id, license_key)
            print_centered(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}ID generated and saved!{Style.RESET_ALL}", width=80)
            print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}", width=80)
            input(" " * 35)
            
        elif choice == "3" or choice == "exit":
            print_centered(f"\n{Fore.WHITE}[{get_color('light')}-{Fore.WHITE}]{Style.RESET_ALL} {Fore.WHITE}Exiting...{Style.RESET_ALL}", width=80)
            time.sleep(1)
            sys.exit(0)
            
        else:
            print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Invalid option{Style.RESET_ALL}", width=80)
            print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}", width=80)
            input(" " * 35)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Interrupted{Style.RESET_ALL}", width=80)
        sys.exit(0)
