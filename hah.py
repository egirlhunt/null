import sys
import time
import os
import json
import random
import asyncio
import discord
from discord.ext import commands
from colorama import init, Fore, Style

init(autoreset=True)

# ────────────────────────────────────────────────────────────────────────────────
#   SELFBOT CATEGORY - USES USER TOKENS ONLY (STRICTLY USER TOKENS)
# ────────────────────────────────────────────────────────────────────────────────

# Global variables for selfbot
selfbot_running = False
running_bots = []
bot_tasks = []
copycat_users = set()
current_prefix = "."

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

# Files
SELFBOT_TOKENS_FILE = "selfbot_tokens.json"
SELFBOT_CONFIG_FILE = "config.json"

def clear_console():
    """Clear console"""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_centered(text):
    """Print text centered in console"""
    try:
        width = os.get_terminal_size().columns
    except:
        width = 80
    
    lines = text.split("\n")
    for line in lines:
        if line.strip():
            print(line.center(width))
        else:
            print()

def display_selfbot_ascii():
    """Display Selfbot ASCII art"""
    clear_console()
    for line in SELFBOT_ASCII_LINES:
        print_centered(line)
    print_centered("made by @uekv on discord")
    print_centered("─"*60)

def display_selfbot_menu():
    """Display Selfbot main menu"""
    display_selfbot_ascii()
    print_centered(f"\n{Fore.CYAN}[+]{Style.RESET_ALL} {Fore.WHITE}Selfbot Menu (USER TOKENS ONLY)")
    print_centered(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}This category requires USER tokens ONLY from browser")
    print_centered(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Get token: F12 → Application → Local Storage → token")
    print_centered(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}BOT TOKENS WILL BE REJECTED HERE")
    print_centered(f"\n{Fore.YELLOW}─" * 60)
    
    options = [
        f"{Fore.CYAN}[1]{Style.RESET_ALL}{Fore.WHITE} Setup wizard",
        f"{Fore.CYAN}[2]{Style.RESET_ALL}{Fore.WHITE} Start bots",
        f"{Fore.CYAN}[3]{Style.RESET_ALL}{Fore.WHITE} Stop bots",
        f"{Fore.CYAN}[4]{Style.RESET_ALL}{Fore.WHITE} Status",
        f"{Fore.CYAN}[5]{Style.RESET_ALL}{Fore.WHITE} Edit Config",
        f"{Fore.CYAN}[0]{Style.RESET_ALL}{Fore.WHITE} ← Back"
    ]
    
    for opt in options:
        print_centered(opt)
    
    print_centered(f"\n{Fore.YELLOW}─" * 60)
    print(f"\n{Fore.CYAN}[+]{Style.RESET_ALL} {Fore.WHITE}Select > ", end="")
    return input().strip()

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
    default_config = {
        "RpcClientID": "",
        "Rpcstate": "Playing Birth Selfbot",
        "Rpcdetails": "",
        "large_image": "",
        "small_image": "jjejjdjdj",
        "large_text": "",
        "party_id": "roster332289",
        "ButtonLabel": "Roster",
        "ButtonLabel1url": "https://discord.gg/roster",
        "ButtonLabel2": "guns.lol/firearm",
        "ButtonLabel2url": "https://guns.lol/firearm",
        "NukeServerBypass": "1289325760040927264"
    }
    
    if not os.path.exists(SELFBOT_CONFIG_FILE):
        with open(SELFBOT_CONFIG_FILE, "w") as f:
            json.dump(default_config, f, indent=2)
        return default_config
    
    try:
        with open(SELFBOT_CONFIG_FILE, "r") as f:
            config = json.load(f)
            for key in default_config:
                if key not in config:
                    config[key] = default_config[key]
            return config
    except:
        return default_config

def save_selfbot_config(config):
    """Save selfbot config to file"""
    try:
        with open(SELFBOT_CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
        return True
    except:
        return False

def edit_config_menu():
    """Edit selfbot configuration"""
    config = load_selfbot_config()
    
    display_selfbot_ascii()
    print_centered(f"\n{Fore.CYAN}[+]{Style.RESET_ALL} {Fore.WHITE}Edit Config.json")
    print_centered(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to keep current value")
    print_centered(f"\n{Fore.YELLOW}─" * 60)
    
    for key, value in config.items():
        new_value = input(f"\n{Fore.CYAN}[?]{Style.RESET_ALL} {Fore.WHITE}{key} [{value}] > ").strip()
        if new_value:
            config[key] = new_value
    
    if save_selfbot_config(config):
        print_centered(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}Config saved!")
    else:
        print_centered(f"\n{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Failed to save")
    
    input(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter...")

class SelfBot(commands.Bot):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.deleted_messages = {}
        self.token = None

    async def on_ready(self):
        print(f"{Fore.GREEN}[ONLINE] Logged in as {self.user} (USER ACCOUNT){Style.RESET_ALL}")
        
        # Apply custom RPC from config.json
        rpc_config = load_selfbot_config()
        if rpc_config:
            state = rpc_config.get("Rpcstate", "Birth Selfbot")
            act = discord.Game(name=state)
            await self.change_presence(activity=act)
            print(f"{Fore.CYAN}[RPC] Applied custom presence: {state}{Style.RESET_ALL}")
        
        print(f"{Fore.YELLOW}[INFO] Selfbot is ready! Use prefix '{self.command_prefix}' for commands{Style.RESET_ALL}")

    @commands.command()
    async def spam(self, ctx, count: int, *, message: str):
        """Send multiple messages"""
        count = min(count, 50)
        for _ in range(count):
            await ctx.send(message)
            await asyncio.sleep(0.8 + random.random() * 0.7)

    @commands.command()
    async def copycat(self, ctx, member: discord.Member):
        """Copy another user's messages"""
        if member == ctx.author:
            await ctx.send("```Can't copy yourself.```")
            return
        copycat_users.add(str(member.id))
        await ctx.send(f"```Copycatting {member.display_name}```")

    @commands.command()
    async def copycat_stop(self, ctx):
        """Stop copycatting"""
        copycat_users.clear()
        await ctx.send("```Copycat stopped.```")

    @commands.command(name="stopchatpack")
    async def stopchatpack(self, ctx):
        """Stop chatpack"""
        copycat_users.clear()
        await ctx.send("```Chatpack / copycat stopped.```")

    @commands.command()
    async def purge(self, ctx, limit: int = 50):
        """Delete your own messages"""
        deleted = 0
        async for msg in ctx.channel.history(limit=min(limit, 100)):
            if msg.author == ctx.author:
                await msg.delete()
                deleted += 1
        await ctx.send(f"```Purged {deleted} messages.```", delete_after=5)

    @commands.command()
    async def chatpack(self, ctx, member: discord.Member):
        """Send random insult"""
        line = random.choice(BEEF_LINES)
        await ctx.send(f"{member.mention} {line}")

    @commands.command()
    async def beef(self, ctx, member: discord.Member):
        """Spam insults at user"""
        for _ in range(10):
            line = random.choice(BEEF_LINES)
            await ctx.send(f"{member.mention} {line}")
            await asyncio.sleep(1.2 + random.random() * 0.8)

    @commands.command()
    async def tspam(self, ctx, count: int, *, message: str):
        """All tokens spam simultaneously"""
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

    @commands.command()
    async def snipe(self, ctx):
        """View deleted messages"""
        cid = str(ctx.channel.id)
        if cid in self.deleted_messages:
            d = self.deleted_messages[cid]
            await ctx.send(f"```Snipe:\nAuthor: {d['author']}\nTime: {d['time']}\nContent: {d['content']}```")
        else:
            await ctx.send("```Nothing sniped.```")

async def launch_selfbot_instance(token, prefix, is_main=False):
    """Launch a single selfbot instance"""
    global bot_tasks, running_bots
    
    # Clean the token
    clean_token = token.strip().replace('"', '').replace("'", '')
    
    # Remove Bot prefix if accidentally added
    if clean_token.startswith('Bot ') or clean_token.startswith('bot '):
        clean_token = clean_token[4:].strip()
    
    if len(clean_token) < 10:
        print(f"{Fore.RED}[ERROR] Invalid token!{Style.RESET_ALL}")
        return False
    
    print(f"{Fore.YELLOW}[INFO] Preparing {'MAIN' if is_main else 'ALT'} token...{Style.RESET_ALL}")
    
    # Create selfbot instance with all intents
    intents = discord.Intents.all()
    intents.messages = True
    intents.guilds = True
    intents.members = True
    intents.message_content = True
    intents.presences = True
    
    bot = SelfBot(command_prefix=prefix, intents=intents, help_command=None)
    bot.token = clean_token
    
    async def run_bot():
        try:
            # Run the bot in selfbot mode (bot=False for user accounts)
            await bot.start(clean_token, bot=False)
        except discord.LoginFailure:
            print(f"{Fore.RED}[ERROR] Login failed for {'MAIN' if is_main else 'ALT'}: Invalid token{Style.RESET_ALL}")
            if bot in running_bots:
                running_bots.remove(bot)
        except Exception as e:
            print(f"{Fore.RED}[ERROR] Failed to start {'MAIN' if is_main else 'ALT'}: {type(e).__name__}{Style.RESET_ALL}")
            if bot in running_bots:
                running_bots.remove(bot)
    
    # Add bot to running list
    running_bots.append(bot)
    
    # Create and store task
    task = asyncio.create_task(run_bot())
    bot_tasks.append(task)
    
    return True

async def start_selfbot_tokens():
    """Start all selfbot instances - FIXED VERSION"""
    global selfbot_running, bot_tasks, running_bots
    
    if selfbot_running:
        print_centered(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Selfbot already running")
        return
    
    data = load_selfbot_tokens()
    main = data.get("main")
    alts = data.get("alts", [])
    prefix = data.get("prefix", ".")
    
    if not main:
        print_centered(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}No main USER token found. Run setup first.")
        return
    
    display_selfbot_ascii()
    print_centered(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Launching main + {len(alts)} alt USER token(s)...")
    print_centered(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Using USER tokens ONLY (selfbot mode)")
    print_centered(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Make sure Message Content Intent is ENABLED in Discord Settings!")
    print_centered(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}This may take a moment...")
    
    # Clear any previous tasks
    for task in bot_tasks:
        task.cancel()
    bot_tasks.clear()
    running_bots.clear()
    
    # Launch all bots
    launch_tasks = []
    
    # Launch main bot
    launch_tasks.append(launch_selfbot_instance(main, prefix, True))
    
    # Launch alts
    for token in alts:
        launch_tasks.append(launch_selfbot_instance(token, prefix))
    
    # Wait for all launch attempts
    results = await asyncio.gather(*launch_tasks, return_exceptions=True)
    
    selfbot_running = True
    
    print_centered(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}All USER bots launched!")
    print_centered(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Prefix: {prefix} | Commands: spam, copycat, purge, etc.")
    print_centered(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Bots should come online shortly...")
    
    # Wait a bit for bots to connect
    await asyncio.sleep(3)
    
    # Check which bots are online
    online_count = 0
    for bot in running_bots:
        if hasattr(bot, 'user') and bot.is_ready():
            online_count += 1
    
    print_centered(f"{Fore.CYAN}[INFO]{Style.RESET_ALL} {Fore.CYAN}{online_count}/{len(running_bots)} bots online")

def stop_selfbot_tokens():
    """Stop all selfbot instances"""
    global selfbot_running, bot_tasks, running_bots
    
    if not selfbot_running:
        print_centered(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Selfbot not running")
        return
    
    print_centered(f"{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Stopping {len(running_bots)} USER bot(s)...")
    
    # Cancel all bot tasks
    for task in bot_tasks:
        task.cancel()
    
    # Close all bots
    for bot in running_bots:
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                loop.create_task(bot.close())
        except:
            pass
    
    # Clear lists
    bot_tasks.clear()
    running_bots.clear()
    selfbot_running = False
    
    print_centered(f"{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}All USER bots stopped")

async def run_selfbot_setup():
    """Run selfbot setup wizard"""
    display_selfbot_ascii()
    print_centered(f"{Fore.CYAN}[+]{Style.RESET_ALL} {Fore.WHITE}Selfbot Setup Wizard (USER TOKENS ONLY)")
    
    main_token = input(f"\n{Fore.CYAN}[?]{Style.RESET_ALL} {Fore.WHITE}Main USER token > ").strip()
    
    if not main_token:
        print_centered(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Cancelled")
        return False
    
    clean_token = main_token.strip().replace('"', '').replace("'", "")
    
    if len(clean_token) < 10:
        print_centered(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Token looks too short")
        return False
    
    alts = []
    print_centered(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Enter alt USER tokens (empty to finish)")
    
    while True:
        alt_token = input(f"{Fore.CYAN}[?]{Style.RESET_ALL} {Fore.WHITE}Alt USER token > ").strip()
        if not alt_token:
            break
        
        clean_alt = alt_token.strip().replace('"', '').replace("'", "")
        if len(clean_alt) < 10:
            print_centered(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Alt token looks too short - skipped")
            continue
        
        alts.append(clean_alt)
        print_centered(f"{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}Added alt token")
    
    prefix = input(f"\n{Fore.CYAN}[?]{Style.RESET_ALL} {Fore.WHITE}Command prefix [default .] > ").strip() or "."
    
    data = {"main": clean_token, "alts": alts, "prefix": prefix}
    if save_selfbot_tokens(data):
        print_centered(f"{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}Setup complete! Saved {len(alts) + 1} USER token(s)")
        return True
    else:
        print_centered(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Failed to save tokens")
        return False

def show_selfbot_status():
    """Show selfbot status"""
    data = load_selfbot_tokens()
    main_exists = bool(data.get("main"))
    alt_count = len(data.get("alts", []))
    
    display_selfbot_ascii()
    print_centered(f"\n{Fore.CYAN}[+]{Style.RESET_ALL} {Fore.WHITE}Selfbot Status (USER TOKENS ONLY)")
    print_centered(f"{Fore.YELLOW}─" * 60)
    
    status = "Running" if selfbot_running else "Stopped"
    print_centered(f"{Fore.CYAN}[Status]{Style.RESET_ALL} {Fore.CYAN}{status}")
    print_centered(f"{Fore.CYAN}[Bots]{Style.RESET_ALL} {Fore.CYAN}{len(running_bots)} active / {alt_count + 1 if main_exists else 0} total")
    print_centered(f"{Fore.CYAN}[Main]{Style.RESET_ALL} {Fore.CYAN}{'Configured' if main_exists else 'Not configured'}")
    print_centered(f"{Fore.CYAN}[Alts]{Style.RESET_ALL} {Fore.CYAN}{alt_count} configured")
    print_centered(f"{Fore.CYAN}[Prefix]{Style.RESET_ALL} {Fore.CYAN}{data.get('prefix', '.')}")
    
    if selfbot_running and running_bots:
        print_centered(f"\n{Fore.CYAN}[Active Bots]{Style.RESET_ALL}")
        for i, bot in enumerate(running_bots):
            if hasattr(bot, 'user'):
                status = f"{Fore.GREEN}Online" if bot.is_ready() else f"{Fore.YELLOW}Connecting"
                print_centered(f"  {Fore.CYAN}[{i+1}]{Style.RESET_ALL} {bot.user} - {status}")
    
    print_centered(f"\n{Fore.YELLOW}─" * 60)
    input(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...")

async def handle_selfbot():
    """Handle selfbot category"""
    while True:
        choice = display_selfbot_menu()
        
        if choice == "1":
            await run_selfbot_setup()
            input(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...")
            
        elif choice == "2":
            try:
                # Create a new event loop for running async tasks
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                loop.run_until_complete(start_selfbot_tokens())
            except Exception as e:
                print(f"{Fore.RED}[ERROR] Failed to start selfbot: {e}{Style.RESET_ALL}")
            input(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...")
            
        elif choice == "3":
            stop_selfbot_tokens()
            input(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...")
            
        elif choice == "4":
            show_selfbot_status()
            
        elif choice == "5":
            edit_config_menu()
            
        elif choice == "0":
            break
            
        else:
            print_centered(f"\n{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Invalid option")
            input(f"\n{Fore.YELLOW}[!]{Style.RESET_ALL} {Fore.YELLOW}Press Enter to continue...")

# ────────────────────────────────────────────────────────────────────────────────
#   MAIN FUNCTION TO TEST SELFBOT
# ────────────────────────────────────────────────────────────────────────────────

def main():
    """Main function to test selfbot"""
    print(f"\n{Fore.CYAN}[+] Starting Selfbot Test...{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[!] Press Ctrl+C to exit{Style.RESET_ALL}")
    
    try:
        # Run the selfbot handler
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(handle_selfbot())
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Exiting...{Style.RESET_ALL}")
        stop_selfbot_tokens()
    except Exception as e:
        print(f"{Fore.RED}[ERROR] {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
