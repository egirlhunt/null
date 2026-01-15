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

# Color themes
COLOR_THEMES = {
    "1": {"name": "Red", "primary": Fore.RED, "secondary": Fore.LIGHTRED_EX, "gradient": 160},
    "2": {"name": "Blue", "primary": Fore.BLUE, "secondary": Fore.LIGHTBLUE_EX, "gradient": 21},
    "3": {"name": "Green", "primary": Fore.GREEN, "secondary": Fore.LIGHTGREEN_EX, "gradient": 46},
    "4": {"name": "Purple", "primary": Fore.MAGENTA, "secondary": Fore.LIGHTMAGENTA_EX, "gradient": 127},
    "5": {"name": "Cyan", "primary": Fore.CYAN, "secondary": Fore.LIGHTCYAN_EX, "gradient": 51},
    "6": {"name": "Yellow", "primary": Fore.YELLOW, "secondary": Fore.LIGHTYELLOW_EX, "gradient": 226},
    "7": {"name": "White", "primary": Fore.WHITE, "secondary": Fore.LIGHTWHITE_EX, "gradient": 15},
    "8": {"name": "Orange", "primary": "\033[38;5;208m", "secondary": "\033[38;5;214m", "gradient": 208},
    "9": {"name": "Pink", "primary": "\033[38;5;213m", "secondary": "\033[38;5;219m", "gradient": 213},
    "10": {"name": "Rainbow", "primary": Fore.WHITE, "secondary": Fore.WHITE, "gradient": "rainbow"}
}

# Current theme (default to red)
current_theme = COLOR_THEMES["1"]
current_gradient_color = 160

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
    
    print(f"{current_theme['primary']}[+]{Style.RESET_ALL} {Fore.WHITE}ID saved to ID.txt{Style.RESET_ALL}")
    print(f"{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.YELLOW}Keep this file safe! Never share it!{Style.RESET_ALL}")

def fetch_license_data():
    """Fetch and parse license data from private GitHub repository"""
    try:
        github_token = get_github_token()
        if not github_token:
            print(f"{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.RED}Failed to decrypt GitHub token{Style.RESET_ALL}")
            return []
        
        print(f"{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.YELLOW}Connecting to private database...{Style.RESET_ALL}")
        
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        response = requests.get(GITHUB_API_URL, headers=headers, timeout=10)
        
        if response.status_code == 200:
            file_info = response.json()
            content = base64.b64decode(file_info["content"]).decode('utf-8')
            licenses = json.loads(content)
            print(f"{current_theme['primary']}[+]{Style.RESET_ALL} {Fore.GREEN}Private database connected successfully{Style.RESET_ALL}")
            print(f"{current_theme['primary']}[•]{Style.RESET_ALL} {Fore.WHITE}Found {len(licenses)} licenses in database{Style.RESET_ALL}")
            return licenses
        elif response.status_code == 404:
            print(f"{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.RED}File not found{Style.RESET_ALL}")
        elif response.status_code == 401:
            print(f"{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.RED}Authentication failed{Style.RESET_ALL}")
        elif response.status_code == 403:
            print(f"{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.RED}Access forbidden{Style.RESET_ALL}")
        else:
            print(f"{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.RED}Database connection failed: {response.status_code}{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.RED}Database error: {e}{Style.RESET_ALL}")
    
    return []

def update_license_data(license_key, new_hwid, new_id=""):
    """Update license data in private GitHub repository"""
    try:
        github_token = get_github_token()
        if not github_token:
            print(f"{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.RED}Failed to decrypt GitHub token{Style.RESET_ALL}")
            return False
        
        # Get current file info
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        response = requests.get(GITHUB_API_URL, headers=headers, timeout=10)
        if response.status_code != 200:
            print(f"{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.RED}Failed to access database: {response.status_code}{Style.RESET_ALL}")
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
            print(f"{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.YELLOW}License not found in database{Style.RESET_ALL}")
            return False
        
        # Update file on GitHub
        update_data = {
            "message": f"Update HWID/ID for {license_key[:8]}...",
            "content": base64.b64encode(json.dumps(licenses, indent=2).encode()).decode(),
            "sha": current_sha
        }
        
        update_response = requests.put(GITHUB_API_URL, headers=headers, json=update_data, timeout=10)
        
        if update_response.status_code in [200, 201]:
            print(f"{current_theme['primary']}[+]{Style.RESET_ALL} {Fore.GREEN}Private database updated successfully{Style.RESET_ALL}")
            return True
        else:
            print(f"{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.RED}Database update failed: {update_response.status_code}{Style.RESET_ALL}")
            return False
            
    except Exception as e:
        print(f"{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.RED}Update error: {e}{Style.RESET_ALL}")
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
            print(f"{current_theme['primary']}[+]{Style.RESET_ALL} {Fore.GREEN}Registration logged{Style.RESET_ALL}")
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
    
    gradient_colors = [
        f"\033[38;5;{current_gradient_color}m", f"\033[38;5;{current_gradient_color}m",
        f"\033[38;5;{current_gradient_color}m", f"\033[38;5;{current_gradient_color}m",
        f"\033[38;5;{current_gradient_color}m", f"\033[38;5;{current_gradient_color}m",
        f"\033[38;5;{current_gradient_color}m", f"\033[38;5;{current_gradient_color}m",
        f"\033[38;5;{current_gradient_color}m", f"\033[38;5;{current_gradient_color}m",
        f"\033[38;5;{current_gradient_color}m", f"\033[38;5;{current_gradient_color}m",
        f"\033[38;5;{current_gradient_color}m", f"\033[38;5;{current_gradient_color}m",
        f"\033[38;5;{current_gradient_color}m", f"\033[38;5;{current_gradient_color}m",
        f"\033[38;5;{current_gradient_color}m", f"\033[38;5;{current_gradient_color}m",
        f"\033[38;5;{current_gradient_color}m"
    ]
    
    if current_gradient_color == "rainbow":
        gradient_colors = [
            "\033[38;5;196m", "\033[38;5;202m", "\033[38;5;208m", "\033[38;5;214m",
            "\033[38;5;220m", "\033[38;5;226m", "\033[38;5;190m", "\033[38;5;154m",
            "\033[38;5;118m", "\033[38;5;82m", "\033[38;5;46m", "\033[38;5;47m",
            "\033[38;5;48m", "\033[38;5;49m", "\033[38;5;50m", "\033[38;5;51m",
            "\033[38;5;45m", "\033[38;5;39m", "\033[38;5;33m"
        ]
    
    reset = "\033[0m"
    gradient_line = f"\033[38;5;{current_gradient_color}m" + "-" * 50 + reset
    
    # Display graphic art with gradient
    for i, line in enumerate(ascii_graphic):
        if current_gradient_color == "rainbow":
            color = gradient_colors[i % len(gradient_colors)]
        else:
            color = gradient_colors[i] if i < len(gradient_colors) else f"\033[38;5;{current_gradient_color}m"
        print(f"{color}{line}{reset}")
    
    print("\n")
    
    # Display text art with gradient
    for i, line in enumerate(ascii_text):
        if current_gradient_color == "rainbow":
            color = gradient_colors[(i + 5) % len(gradient_colors)]
        else:
            color = gradient_colors[i] if i < len(gradient_colors) else f"\033[38;5;{current_gradient_color}m"
        print(f"{color}{line}{reset}")
    
    print("\n")
    
    # Add "made by @uekv on discord"
    print(f"{current_theme['secondary']}made by @uekv on discord{Style.RESET_ALL}")
    print(gradient_line)

def display_gradient_ascii():
    """Full display with license prompt"""
    display_gradient_ascii_header_only()
    print(f"\n{current_theme['primary']}[+]{Style.RESET_ALL} {Fore.WHITE}Enter License Key > {Style.RESET_ALL}", end="")

def display_color_selection():
    """Display color selection menu"""
    clear_screen_preserve_header()
    
    print(f"\n{current_theme['primary']}[+]{Style.RESET_ALL} {Fore.WHITE}Color Selection Menu{Style.RESET_ALL}\n")
    
    box_width = 25
    horizontal_line = "─" * (box_width * 2 + 8)
    
    # Print top border
    print(f"{current_theme['primary']}┌{horizontal_line}┐{Style.RESET_ALL}")
    
    # Display colors in 2 columns
    for i in range(0, 10, 2):
        line = f"{current_theme['primary']}│{Style.RESET_ALL}"
        
        # Column 1
        key1 = str(i+1)
        theme1 = COLOR_THEMES[key1]
        padding1 = (box_width - len(f"[{key1}] {theme1['name']}")) // 2
        left_pad1 = " " * padding1
        right_pad1 = " " * (box_width - len(f"[{key1}] {theme1['name']}") - padding1)
        colored_option1 = f"{theme1['primary']}[{key1}]{Style.RESET_ALL}{Fore.WHITE} {theme1['name']}{Style.RESET_ALL}"
        line += f" {left_pad1}{colored_option1}{right_pad1} {current_theme['primary']}│{Style.RESET_ALL}"
        
        # Column 2
        if i+1 < 10:
            key2 = str(i+2)
            theme2 = COLOR_THEMES[key2]
            padding2 = (box_width - len(f"[{key2}] {theme2['name']}")) // 2
            left_pad2 = " " * padding2
            right_pad2 = " " * (box_width - len(f"[{key2}] {theme2['name']}") - padding2)
            colored_option2 = f"{theme2['primary']}[{key2}]{Style.RESET_ALL}{Fore.WHITE} {theme2['name']}{Style.RESET_ALL}"
            line += f" {left_pad2}{colored_option2}{right_pad2} {current_theme['primary']}│{Style.RESET_ALL}"
        
        print(line)
        
        if i < 8:
            print(f"{current_theme['primary']}├{horizontal_line}┤{Style.RESET_ALL}")
    
    # Print bottom border
    print(f"{current_theme['primary']}└{horizontal_line}┘{Style.RESET_ALL}")
    
    print("\n" + f"\033[38;5;{current_gradient_color}m" + "-" * 50 + "\033[0m")
    
    return input(f"\n{current_theme['primary']}[+]{Style.RESET_ALL} {Fore.WHITE}Select Color > {Style.RESET_ALL}")

def display_options_grid():
    """Display options in a box-like grid format"""
    clear_screen_preserve_header()
    
    options = [
        [f"{current_theme['primary']}[1]{Style.RESET_ALL} Change Color", f"{current_theme['primary']}[2]{Style.RESET_ALL} Generate ID", f"{current_theme['primary']}[3]{Style.RESET_ALL} Exit"]
    ]
    
    print(f"\n{current_theme['primary']}[+]{Style.RESET_ALL} {Fore.WHITE}Main Menu - Welcome!{Style.RESET_ALL}\n")
    
    # Calculate box width
    box_width = 30
    horizontal_line = "─" * (box_width * 3 + 8)
    
    # Print top border
    print(f"{current_theme['primary']}┌{horizontal_line}┐{Style.RESET_ALL}")
    
    # Print options
    for row in options:
        line = f"{current_theme['primary']}│{Style.RESET_ALL}"
        for option in row:
            # Center each option in its box
            padding = (box_width - len(option) + 15) // 2  # Adjust for ANSI codes
            left_pad = " " * padding
            right_pad = " " * (box_width - len(option) + 15 - padding)
            line += f" {left_pad}{option}{right_pad} {current_theme['primary']}│{Style.RESET_ALL}"
        print(line)
    
    # Print bottom border
    print(f"{current_theme['primary']}└{horizontal_line}┘{Style.RESET_ALL}")
    
    print("\n" + f"\033[38;5;{current_gradient_color}m" + "-" * 50 + "\033[0m")
    
    return input(f"\n{current_theme['primary']}[+]{Style.RESET_ALL} {Fore.WHITE}Select > {Style.RESET_ALL}")

def validate_license_key():
    """Validate license key against private GitHub database"""
    user_key = input().strip()
    
    if not user_key:
        print(f"\n{current_theme['primary']}[-]{Style.RESET_ALL} {Fore.RED}No license key entered!{Style.RESET_ALL}")
        return False, ""
    
    print(f"\n{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.YELLOW}Checking private database...{Style.RESET_ALL}")
    time.sleep(1)
    
    try:
        # Fetch license data from private GitHub database
        licenses = fetch_license_data()
        
        if not licenses:
            print(f"{current_theme['primary']}[-]{Style.RESET_ALL} {Fore.RED}Private database connection failed{Style.RESET_ALL}")
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
                    print(f"{current_theme['primary']}[+]{Style.RESET_ALL} {Fore.GREEN}New activation detected{Style.RESET_ALL}")
                    
                    # Generate ID if not exists
                    if not user_id:
                        user_id = generate_random_id()
                        print(f"{current_theme['primary']}[+]{Style.RESET_ALL} {Fore.GREEN}Generated User ID: {user_id}{Style.RESET_ALL}")
                        save_id_to_file(user_id, user_key)
                    
                    # Send webhook notification
                    send_webhook(user_key, current_hwid, user_id)
                    
                    # Update GitHub database with HWID and ID
                    print(f"{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.YELLOW}Updating private database...{Style.RESET_ALL}")
                    if update_license_data(user_key, current_hwid, user_id):
                        print(f"{current_theme['primary']}[+]{Style.RESET_ALL} {Fore.GREEN}License activated!{Style.RESET_ALL}")
                        time.sleep(2)
                        return True, user_key
                    else:
                        print(f"{current_theme['primary']}[-]{Style.RESET_ALL} {Fore.RED}Database update failed{Style.RESET_ALL}")
                        return False, ""
                else:
                    # Check HWID match
                    if stored_hwid == current_hwid:
                        print(f"{current_theme['primary']}[+]{Style.RESET_ALL} {Fore.GREEN}Hardware verified{Style.RESET_ALL}")
                        if user_id and not os.path.exists("ID.txt"):
                            save_id_to_file(user_id, user_key)
                        time.sleep(1)
                        return True, user_key
                    else:
                        print(f"{current_theme['primary']}[-]{Style.RESET_ALL} {Fore.RED}Hardware mismatch!{Style.RESET_ALL}")
                        print(f"{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.RED}Your HWID: {current_hwid[:16]}...{Style.RESET_ALL}")
                        print(f"{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.RED}Database HWID: {stored_hwid[:16]}...{Style.RESET_ALL}")
                        print(f"\n{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.RED}If this is a mistake, DM @uekv{Style.RESET_ALL}")
                        
                        for i in range(10, 0, -1):
                            print(f"{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.RED}Closing in {i}...{Style.RESET_ALL}")
                            time.sleep(1)
                        return False, ""
        
        if not license_found:
            print(f"\n{current_theme['primary']}[-]{Style.RESET_ALL} {Fore.RED}License not found in private database!{Style.RESET_ALL}")
            print(f"{current_theme['primary']}[-]{Style.RESET_ALL} {Fore.RED}Closing in 3 seconds...{Style.RESET_ALL}")
            
            for i in range(3, 0, -1):
                print(f"{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.RED}Closing in {i}...{Style.RESET_ALL}")
                time.sleep(1)
            
            return False, ""
            
    except Exception as e:
        print(f"{current_theme['primary']}[-]{Style.RESET_ALL} {Fore.RED}Database error: {e}{Style.RESET_ALL}")
        return False, ""
    
    return False, ""

def main():
    global current_theme, current_gradient_color
    
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
                if color_choice == "10":  # Rainbow
                    current_gradient_color = "rainbow"
                else:
                    current_gradient_color = current_theme["gradient"]
                print(f"\n{current_theme['primary']}[+]{Style.RESET_ALL} {Fore.WHITE}Color changed to {current_theme['name']}{Style.RESET_ALL}")
            else:
                print(f"\n{current_theme['primary']}[-]{Style.RESET_ALL} {Fore.RED}Invalid color choice{Style.RESET_ALL}")
            input(f"\n{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            
        elif choice == "2":
            # Generate ID
            print(f"\n{current_theme['primary']}[+]{Style.RESET_ALL} {Fore.GREEN}Generating new ID...{Style.RESET_ALL}")
            
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
            print(f"{current_theme['primary']}[+]{Style.RESET_ALL} {Fore.GREEN}ID generated and saved!{Style.RESET_ALL}")
            input(f"\n{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            
        elif choice == "3" or choice == "exit":
            print(f"\n{Fore.WHITE}[{current_theme['primary']}-{Fore.WHITE}]{Style.RESET_ALL} {Fore.WHITE}Exiting...{Style.RESET_ALL}")
            time.sleep(1)
            sys.exit(0)
            
        else:
            print(f"\n{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.YELLOW}Invalid option{Style.RESET_ALL}")
            input(f"\n{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{current_theme['primary']}[!]{Style.RESET_ALL} {Fore.RED}Interrupted{Style.RESET_ALL}")
        sys.exit(0)
