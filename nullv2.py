#!/usr/bin/env python3
import sys
import time
import os
import json
import hashlib
import uuid
import requests
import base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from colorama import init, Fore, Style

init(autoreset=True)

# Encryption settings
PASSPHRASE = "fdfac521-be53-4ed5-b7a0-47606a2f3821"

# Encrypted tokens
ENCRYPTED_GITHUB_TOKEN = "U2FsdGVkX1+sb+WhlbvskKQEcmA7M/zl91awuHfgDt7FOmO8cBHp7kl1qgRKm0j4UR/8VaO0OUA6YqschJEsVHPxinmIgU9DsXsd1S7a//DYAu2H6ruBIMDDdx3GiuW0Gw7A7l0n4+vbAg1y8kTVBg=="
ENCRYPTED_WEBHOOK = "U2FsdGVkX1+Nw4U/zl83/gKNEByPtf6hHZCyga+N6cKvQZNTQgo9fp4UjeajxHOySDCuZhv6PbgzS+VtCTMzE6ULKXqHChvUSVKiQRxjINzWrVIyWBMs2B3QwUZYflKrEJYj25kQ4wCcLaRIMJUmuoKpmpmKy+5oLz5Bi9FjYzOv8ftNm7Ye41t6Sy87Prwz"

# GitHub repository information
REPO_OWNER = "egirlhunt"
REPO_NAME = "nulllkeys"
FILE_PATH = "keys.json"

# GitHub API URL
GITHUB_API_URL = f"https://api.github.com/repos/{REPO_OWNER}/{REPO_NAME}/contents/{FILE_PATH}"

def decrypt_aes(encrypted_text, passphrase):
    """Decrypt AES-256-CBC encrypted text"""
    try:
        # Decode base64
        encrypted_data = base64.b64decode(encrypted_text)
        
        # Extract salt and ciphertext (first 8 bytes is "Salted__", next 8 bytes is salt)
        salt = encrypted_data[8:16]
        ciphertext = encrypted_data[16:]
        
        # Derive key and IV using OpenSSL's EVP_BytesToKey
        key_iv = hashlib.md5(passphrase.encode() + salt).digest()
        key_iv += hashlib.md5(key_iv + passphrase.encode() + salt).digest()
        key = key_iv[:32]
        iv = key_iv[32:48]
        
        # Decrypt
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return decrypted.decode('utf-8')
    except Exception as e:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Decryption error: {e}{Style.RESET_ALL}")
        return ""

def get_github_token():
    """Get decrypted GitHub token"""
    return decrypt_aes(ENCRYPTED_GITHUB_TOKEN, PASSPHRASE)

def get_webhook_url():
    """Get decrypted webhook URL"""
    return decrypt_aes(ENCRYPTED_WEBHOOK, PASSPHRASE)

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
        
        # Get processor info
        if os.name == 'nt':
            import subprocess
            try:
                cpu_info = subprocess.check_output('wmic cpu get ProcessorId', shell=True).decode().strip()
                hwid_parts.append(cpu_info.split('\n')[-1].strip())
            except:
                pass
        
        # Create hash from all parts
        hwid_string = '-'.join(hwid_parts)
        return hashlib.sha256(hwid_string.encode()).hexdigest()[:32]
        
    except Exception as e:
        return str(uuid.getnode())

def fetch_license_data():
    """Fetch and parse license data from private GitHub repository"""
    try:
        github_token = get_github_token()
        if not github_token:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Failed to decrypt GitHub token{Style.RESET_ALL}")
            return []
        
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Connecting to private database...{Style.RESET_ALL}")
        
        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        response = requests.get(GITHUB_API_URL, headers=headers, timeout=10)
        
        if response.status_code == 200:
            file_info = response.json()
            content = base64.b64decode(file_info["content"]).decode('utf-8')
            licenses = json.loads(content)
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}Private database connected successfully{Style.RESET_ALL}")
            return licenses
        elif response.status_code == 404:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}File not found: {GITHUB_API_URL}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Make sure keys.json exists in the repository{Style.RESET_ALL}")
        else:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Database connection failed: {response.status_code}{Style.RESET_ALL}")
            
    except Exception as e:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Database error: {e}{Style.RESET_ALL}")
    
    return []

def update_license_data(license_key, new_hwid):
    """Update license data in private GitHub repository"""
    try:
        github_token = get_github_token()
        if not github_token:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Failed to decrypt GitHub token{Style.RESET_ALL}")
            return False
        
        # Get current file info
        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        response = requests.get(GITHUB_API_URL, headers=headers, timeout=10)
        if response.status_code != 200:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Failed to access database: {response.status_code}{Style.RESET_ALL}")
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
                updated = True
                break
        
        if not updated:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}License not found in database{Style.RESET_ALL}")
            return False
        
        # Update file on GitHub
        update_data = {
            "message": f"Update HWID for {license_key[:8]}...",
            "content": base64.b64encode(json.dumps(licenses, indent=2).encode()).decode(),
            "sha": current_sha
        }
        
        update_response = requests.put(GITHUB_API_URL, headers=headers, json=update_data, timeout=10)
        
        if update_response.status_code in [200, 201]:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}Private database updated successfully{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Database update failed: {update_response.status_code}{Style.RESET_ALL}")
            return False
            
    except Exception as e:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Update error: {e}{Style.RESET_ALL}")
        return False

def send_webhook(license_key, hwid):
    """Send registration to webhook"""
    try:
        webhook_url = get_webhook_url()
        if not webhook_url:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Failed to decrypt webhook URL{Style.RESET_ALL}")
            return
        
        payload = {
            "embeds": [{
                "title": "NEW REGISTRATION",
                "color": 16711680,
                "fields": [
                    {"name": "License key", "value": f"`{license_key}`", "inline": True},
                    {"name": "HWID", "value": f"`{hwid}`", "inline": True}
                ],
                "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())
            }]
        }
        response = requests.post(webhook_url, json=payload, timeout=5)
        if response.status_code in [200, 204]:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}Registration logged to webhook{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Webhook error: {e}{Style.RESET_ALL}")

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
        "\033[38;5;196m", "\033[38;5;196m", "\033[38;5;160m", "\033[38;5;160m",
        "\033[38;5;124m", "\033[38;5;124m", "\033[38;5;160m", "\033[38;5;160m",
        "\033[38;5;196m", "\033[38;5;196m", "\033[38;5;160m", "\033[38;5;160m",
        "\033[38;5;124m", "\033[38;5;124m", "\033[38;5;160m", "\033[38;5;160m",
        "\033[38;5;196m", "\033[38;5;196m", "\033[38;5;160m"
    ]
    
    reset = "\033[0m"
    gradient_line = "\033[38;5;160m" + "-" * 50 + reset
    
    # Display graphic art with gradient
    for i, line in enumerate(ascii_graphic):
        color = gradient_colors[i] if i < len(gradient_colors) else "\033[38;5;160m"
        print(f"{color}{line}{reset}")
    
    print("\n")
    
    # Display text art with gradient
    for i, line in enumerate(ascii_text):
        color = gradient_colors[i] if i < len(gradient_colors) else "\033[38;5;160m"
        print(f"{color}{line}{reset}")
    
    print("\n")
    
    # Add "made by @uekv on discord"
    print(f"{Fore.LIGHTRED_EX}made by @uekv on discord{Style.RESET_ALL}")
    print(gradient_line)

def display_gradient_ascii():
    """Full display with license prompt"""
    display_gradient_ascii_header_only()
    print(f"\n{Fore.RED}[+]{Style.RESET_ALL} {Fore.WHITE}Enter License Key > {Style.RESET_ALL}", end="")

def display_options_grid():
    """Display options in a box-like grid format"""
    clear_screen_preserve_header()
    
    options = [
        ["[1] Start Tool", "[2] Settings", "[3] Key Manager"],
        ["[4] Check HWID", "[5] Help", "[6] About"],
        ["[7] Update", "[8] Exit", "[9] Admin Panel"]
    ]
    
    print(f"\n{Fore.RED}[+]{Style.RESET_ALL} {Fore.WHITE}Main Menu - Welcome!{Style.RESET_ALL}\n")
    
    # Calculate box width
    box_width = 22
    horizontal_line = "─" * (box_width * 3 + 8)
    
    # Print top border
    print(f"{Fore.LIGHTRED_EX}┌{horizontal_line}┐{Style.RESET_ALL}")
    
    # Print options
    for row in options:
        line = f"{Fore.LIGHTRED_EX}│{Style.RESET_ALL}"
        for option in row:
            # Center each option in its box
            padding = (box_width - len(option)) // 2
            left_pad = " " * padding
            right_pad = " " * (box_width - len(option) - padding)
            colored_option = f"{Fore.RED}{option[:3]}{Style.RESET_ALL}{Fore.WHITE}{option[3:]}{Style.RESET_ALL}"
            line += f" {left_pad}{colored_option}{right_pad} {Fore.LIGHTRED_EX}│{Style.RESET_ALL}"
        print(line)
        
        # Add separator between rows
        if row != options[-1]:
            print(f"{Fore.LIGHTRED_EX}├{horizontal_line}┤{Style.RESET_ALL}")
    
    # Print bottom border
    print(f"{Fore.LIGHTRED_EX}└{horizontal_line}┘{Style.RESET_ALL}")
    
    print("\n" + "\033[38;5;160m" + "-" * 50 + "\033[0m")
    
    return input(f"\n{Fore.RED}[+]{Style.RESET_ALL} {Fore.WHITE}Select > {Style.RESET_ALL}")

def validate_license_key():
    """Validate license key against private GitHub database"""
    user_key = input().strip()
    
    if not user_key:
        print(f"\n{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}No license key entered!{Style.RESET_ALL}")
        return False
    
    print(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Checking private database...{Style.RESET_ALL}")
    time.sleep(1)
    
    try:
        # Fetch license data from private GitHub database
        licenses = fetch_license_data()
        
        if not licenses:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Private database connection failed{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Check GitHub token permissions and repository access{Style.RESET_ALL}")
            return False
        
        # Find the license key
        license_found = False
        current_hwid = get_hwid()
        
        for license_entry in licenses:
            if license_entry.get("Licensekey") == user_key:
                license_found = True
                stored_hwid = license_entry.get("hwid", "").strip()
                
                if not stored_hwid:
                    # First time activation
                    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}New activation detected{Style.RESET_ALL}")
                    
                    # Send webhook notification
                    send_webhook(user_key, current_hwid)
                    
                    # Update GitHub database with HWID
                    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Updating private database...{Style.RESET_ALL}")
                    if update_license_data(user_key, current_hwid):
                        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}License activated!{Style.RESET_ALL}")
                        time.sleep(2)
                        return True
                    else:
                        print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Database update failed{Style.RESET_ALL}")
                        return False
                else:
                    # Check HWID match
                    if stored_hwid == current_hwid:
                        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}Hardware verified{Style.RESET_ALL}")
                        time.sleep(1)
                        return True
                    else:
                        print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Hardware mismatch!{Style.RESET_ALL}")
                        print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Your HWID: {current_hwid[:16]}...{Style.RESET_ALL}")
                        print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Database HWID: {stored_hwid[:16]}...{Style.RESET_ALL}")
                        print(f"\n{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}If this is a mistake, DM @uekv{Style.RESET_ALL}")
                        
                        for i in range(10, 0, -1):
                            print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Closing in {i}...{Style.RESET_ALL}")
                            time.sleep(1)
                        return False
        
        if not license_found:
            print(f"\n{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}License not found in private database!{Style.RESET_ALL}")
            print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Closing in 3 seconds...{Style.RESET_ALL}")
            
            for i in range(3, 0, -1):
                print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Closing in {i}...{Style.RESET_ALL}")
                time.sleep(1)
            
            return False
            
    except Exception as e:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Database error: {e}{Style.RESET_ALL}")
        return False

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    display_gradient_ascii()
    
    if not validate_license_key():
        sys.exit(1)
    
    # Main menu loop
    while True:
        choice = display_options_grid()
        
        clear_screen_preserve_header()
        
        if choice == "1":
            print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}Starting main tool...{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Tool functionality would go here{Style.RESET_ALL}")
            input(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            
        elif choice == "2":
            print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}Opening settings...{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[•]{Style.RESET_ALL} {Fore.WHITE}Theme: Red Gradient{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[•]{Style.RESET_ALL} {Fore.WHITE}License: Active{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[•]{Style.RESET_ALL} {Fore.WHITE}Version: 1.0.0{Style.RESET_ALL}")
            input(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            
        elif choice == "3":
            print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}Key Manager{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Connected to private GitHub database{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[•]{Style.RESET_ALL} {Fore.WHITE}Repository: egirlhunt/nulllkeys{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[•]{Style.RESET_ALL} {Fore.WHITE}File: keys.json{Style.RESET_ALL}")
            input(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            
        elif choice == "4":
            current_hwid = get_hwid()
            print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}Your HWID:{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[•]{Style.RESET_ALL} {Fore.WHITE}{current_hwid}{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}This ID is tied to your system{Style.RESET_ALL}")
            input(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            
        elif choice == "8" or choice == "exit":
            print(f"\n{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Exiting...{Style.RESET_ALL}")
            time.sleep(1)
            sys.exit(0)
            
        else:
            print(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Option {choice} selected{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}This feature is under development{Style.RESET_ALL}")
            input(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Interrupted{Style.RESET_ALL}")
        sys.exit(0)
