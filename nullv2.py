#!/usr/bin/env python3
import sys
import time
import os
import json
import hashlib
import hmac
import base64
import requests
import uuid
from colorama import init, Fore, Style

init(autoreset=True)

# Encrypted webhook and GitHub URLs (simple XOR encryption)
WEBHOOK_KEY = "uekv_encryption_key_2024"
GITHUB_KEY = "github_encryption_key_2024"
GITHUB_TOKEN = "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"

def xor_encrypt_decrypt(text, key):
    """Simple XOR encryption/decryption"""
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))

# Encrypted URLs (these appear as gibberish in the code)
encrypted_webhook = xor_encrypt_decrypt("https://canary.discord.com/api/webhooks/1461106633919828185/i-PQYIH8Xa99qLXaTjiY_8zIvRTbkAewYWm0Se3c2Dqf8vWzBUxLf7AC7q5lFCU8orbZ", WEBHOOK_KEY)
encrypted_github_repo = xor_encrypt_decrypt("https://api.github.com/repos/egirlhunt/nulllkeys/contents/keys.json", GITHUB_KEY)
encrypted_github_raw = xor_encrypt_decrypt("https://raw.githubusercontent.com/egirlhunt/nulllkeys/main/keys.json", GITHUB_KEY)

def get_webhook_url():
    return xor_encrypt_decrypt(encrypted_webhook, WEBHOOK_KEY)

def get_github_repo_url():
    return xor_encrypt_decrypt(encrypted_github_repo, GITHUB_KEY)

def get_github_raw_url():
    return xor_encrypt_decrypt(encrypted_github_raw, GITHUB_KEY)

def get_hwid():
    """Generate a unique hardware ID"""
    try:
        # Combine multiple system identifiers
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
        # Fallback to simple UUID
        return str(uuid.getnode())

def fetch_license_data():
    """Fetch and parse license data from GitHub"""
    try:
        response = requests.get(get_github_raw_url(), timeout=10)
        if response.status_code == 200:
            return json.loads(response.text)
    except Exception as e:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Failed to fetch license data: {e}{Style.RESET_ALL}")
    return []

def update_license_data(license_key, new_hwid):
    """Update license data on GitHub with new HWID"""
    try:
        # First, get current file content and SHA
        headers = {
            "Authorization": f"token {GITHUB_TOKEN}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        response = requests.get(get_github_repo_url(), headers=headers, timeout=10)
        if response.status_code != 200:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Failed to get file info: {response.status_code}{Style.RESET_ALL}")
            return False
        
        file_info = response.json()
        current_sha = file_info["sha"]
        current_content = base64.b64decode(file_info["content"]).decode('utf-8')
        
        # Parse and update the JSON
        licenses = json.loads(current_content)
        updated = False
        
        for license_entry in licenses:
            if license_entry.get("Licensekey") == license_key:
                if not license_entry.get("hwid"):
                    license_entry["hwid"] = new_hwid
                    updated = True
                    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}Updated HWID for license{Style.RESET_ALL}")
                break
        
        if not updated:
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}License already has HWID or not found{Style.RESET_ALL}")
            return False
        
        # Prepare new content
        new_content = json.dumps(licenses, indent=2)
        
        # Update file on GitHub
        update_data = {
            "message": f"Update HWID for license {license_key[:8]}...",
            "content": base64.b64encode(new_content.encode()).decode(),
            "sha": current_sha
        }
        
        update_response = requests.put(get_github_repo_url(), 
                                      headers=headers, 
                                      json=update_data, 
                                      timeout=10)
        
        if update_response.status_code in [200, 201]:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}Successfully updated GitHub repository{Style.RESET_ALL}")
            return True
        else:
            print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Failed to update GitHub: {update_response.status_code}{Style.RESET_ALL}")
            return False
            
    except Exception as e:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Update error: {e}{Style.RESET_ALL}")
        return False

def send_webhook(license_key, hwid):
    """Send registration to webhook"""
    try:
        webhook_url = get_webhook_url()
        payload = {
            "embeds": [{
                "title": "NEW REGISTRATION",
                "color": 16711680,  # Red
                "fields": [
                    {"name": "License key", "value": f"`{license_key}`", "inline": True},
                    {"name": "HWID", "value": f"`{hwid}`", "inline": True}
                ],
                "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())
            }]
        }
        response = requests.post(webhook_url, json=payload, timeout=5)
        if response.status_code in [200, 204]:
            print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}Sent webhook notification{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Failed to send webhook: {e}{Style.RESET_ALL}")

def clear_screen_preserve_header():
    """Clear screen but preserve the header"""
    os.system('cls' if os.name == 'nt' else 'clear')
    # Re-print the ascii art (without extra newlines)
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
    """Validate license key against GitHub repository"""
    user_key = input().strip()
    
    if not user_key:
        print(f"\n{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}No license key entered!{Style.RESET_ALL}")
        return False
    
    print(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Validating license...{Style.RESET_ALL}")
    time.sleep(1)
    
    try:
        # Fetch license data from GitHub
        licenses = fetch_license_data()
        
        if not licenses:
            print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}No licenses found in repository{Style.RESET_ALL}")
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
                    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}First activation detected{Style.RESET_ALL}")
                    
                    # Send webhook notification
                    send_webhook(user_key, current_hwid)
                    
                    # Update GitHub repository with HWID
                    print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Updating GitHub repository...{Style.RESET_ALL}")
                    if update_license_data(user_key, current_hwid):
                        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}License activated successfully!{Style.RESET_ALL}")
                        time.sleep(2)
                        return True
                    else:
                        print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Failed to update license data{Style.RESET_ALL}")
                        return False
                else:
                    # Check HWID match
                    if stored_hwid == current_hwid:
                        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}HWID verified - Welcome back!{Style.RESET_ALL}")
                        time.sleep(1)
                        return True
                    else:
                        print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}HWID does not match!{Style.RESET_ALL}")
                        print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Your HWID: {current_hwid[:16]}...{Style.RESET_ALL}")
                        print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Stored HWID: {stored_hwid[:16]}...{Style.RESET_ALL}")
                        print(f"\n{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}If this is a mistake, DM @uekv on Discord{Style.RESET_ALL}")
                        
                        for i in range(10, 0, -1):
                            print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Closing in {i}...{Style.RESET_ALL}")
                            time.sleep(1)
                        return False
        
        if not license_found:
            print(f"\n{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Invalid License Key!{Style.RESET_ALL}")
            print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Tool closing in 3 seconds...{Style.RESET_ALL}")
            
            for i in range(3, 0, -1):
                print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Closing in {i}...{Style.RESET_ALL}")
                time.sleep(1)
            
            return False
            
    except Exception as e:
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Validation error: {e}{Style.RESET_ALL}")
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
            print(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Connected to GitHub repository{Style.RESET_ALL}")
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
