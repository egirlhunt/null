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

# Encrypted webhook and gist URLs (simple XOR encryption)
WEBHOOK_KEY = "uekv_encryption_key_2024"
GIST_KEY = "gist_encryption_key_2024"

def xor_encrypt_decrypt(text, key):
    """Simple XOR encryption/decryption"""
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(text))

# Encrypted URLs (these appear as gibberish in the code)
encrypted_webhook = xor_encrypt_decrypt("https://canary.discord.com/api/webhooks/1461106633919828185/i-PQYIH8Xa99qLXaTjiY_8zIvRTbkAewYWm0Se3c2Dqf8vWzBUxLf7AC7q5lFCU8orbZ", WEBHOOK_KEY)
encrypted_gist = xor_encrypt_decrypt("https://gist.github.com/egirlhunt/a7d3533199a44d27328c1c50d63f24e5/raw", GIST_KEY)

def get_webhook_url():
    return xor_encrypt_decrypt(encrypted_webhook, WEBHOOK_KEY)

def get_gist_url():
    return xor_encrypt_decrypt(encrypted_gist, GIST_KEY)

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
    """Fetch and parse license data from gist"""
    try:
        response = requests.get(get_gist_url(), timeout=10)
        if response.status_code == 200:
            # Clean and parse the JSON
            content = response.text.strip()
            # Remove any trailing commas
            if content.endswith(','):
                content = content[:-1]
            # Ensure it's valid JSON array
            if content.startswith('{') and content.endswith('}'):
                content = '[' + content + ']'
            return json.loads(content)
    except Exception as e:
        print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Failed to fetch license data: {e}{Style.RESET_ALL}")
    return []

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
        requests.post(webhook_url, json=payload, timeout=5)
    except:
        pass  # Silently fail if webhook fails

def update_license_data(license_key, hwid):
    """This would ideally update the gist, but requires GitHub API token"""
    # For now, just sends webhook. In production, you'd need to implement
    # GitHub API calls with proper authentication to update the gist
    pass

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
        ["[1] Start", "[2] Settings", "[3] Tools"],
        ["[4] Config", "[5] Help", "[6] About"],
        ["[7] Update", "[8] Exit", "[9] Debug"]
    ]
    
    print(f"\n{Fore.RED}[+]{Style.RESET_ALL} {Fore.WHITE}Main Menu{Style.RESET_ALL}\n")
    
    # Calculate box width
    box_width = 20
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
    """Validate license key against gist"""
    user_key = input().strip()
    
    if not user_key:
        print(f"\n{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}No license key entered!{Style.RESET_ALL}")
        return False
    
    print(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Validating license...{Style.RESET_ALL}")
    time.sleep(1)
    
    try:
        # Fetch license data from gist
        licenses = fetch_license_data()
        
        # Find the license key
        license_found = False
        hwid_match = False
        current_hwid = get_hwid()
        
        for license_entry in licenses:
            if license_entry.get("Licensekey") == user_key:
                license_found = True
                stored_hwid = license_entry.get("hwid", "").strip()
                
                if not stored_hwid:
                    # First time activation
                    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}First activation detected{Style.RESET_ALL}")
                    send_webhook(user_key, current_hwid)
                    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}License activated!{Style.RESET_ALL}")
                    return True
                else:
                    # Check HWID match
                    if stored_hwid == current_hwid:
                        print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}HWID verified{Style.RESET_ALL}")
                        return True
                    else:
                        print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}HWID does not match!{Style.RESET_ALL}")
                        print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}If this is a mistake, DM @uekv on Discord{Style.RESET_ALL}")
                        
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
            # Add your tool functionality here
            input(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            
        elif choice == "2":
            print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}Opening settings...{Style.RESET_ALL}")
            # Add settings functionality here
            input(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            
        elif choice == "8" or choice == "exit":
            print(f"\n{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Exiting...{Style.RESET_ALL}")
            time.sleep(1)
            sys.exit(0)
            
        else:
            print(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Option {choice} selected{Style.RESET_ALL}")
            # Add other option functionalities here
            input(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Interrupted{Style.RESET_ALL}")
        sys.exit(0)
