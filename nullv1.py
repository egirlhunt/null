import os
import sys
import time

# ────────────────────────────────────────────────
#   Colors (dark red → light red gradient feel)
# ────────────────────────────────────────────────
RED_DARK   = "\033[38;5;88m"
RED_MEDIUM = "\033[38;5;124m"
RED_LIGHT  = "\033[38;5;160m"
RESET      = "\033[0m"
BOLD       = "\033[1m"

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

def print_gradient_line(text, start_color=RED_DARK, end_color=RED_LIGHT):
    print(f"{start_color}{BOLD}{text}{RESET}")

def main():
    # We never clear after the first render → header stays forever
    clear()  # only once at startup

    # ──────────────────────────────────────────────────────────────
    # Big ASCII art (your provided one)
    # ──────────────────────────────────────────────────────────────
    ascii_art = [
        "⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⣤⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀",
        "⠀⠀⠀⠀⠀⡀⣰⡿⠛⠛⠿⢶⣦⣀⠀⢀⣀⣀⣀⣀⣠⡾⠋⠀⠀⠹⣷⣄⣤⣶⡶⠿⠿⣷⡄⠀⠀⠀⠀⠀",
        "⠀⠀⠀⠀⠀⢰⣿⠁⠀⠀⠀⠀⠈⠙⠛⠛⠋⠉⠉⢹⡟⠁⠀⠀⣀⣀⠘⣿⠉⠀⠀⠀⠀⠘⣿⠀⠀⠀⠀⠀",
        "⠀⠀⠀⠀⠀⢸⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠁⠀⠀⣾⡋⣽⠿⠛⠿⢶⣤⣤⣤⣤⣿⠀⠀⠀⠀⠀",
        "⠀⠀⠀⠀⠀⢸⣿⡴⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣄⡀⠀⢈⣻⡏⠀⠀⠀⠀⣿⣀⠀⠈⠙⣷⠀⠀⠀⠀",
        "⠀⠀⠀⠀⠀⣰⡿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠛⠛⠛⠙⢷⣄⣀⣀⣾⣏⣿⠀⠀⢀⣿⠀⠀⠀⠀",
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
        "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀"
    ]

    # ──────────────────────────────────────────────────────────────
    # Print everything in one go — stays on screen forever
    # ──────────────────────────────────────────────────────────────
    print(f"{RED_DARK}{'═' * 80}{RESET}\n")

    # Gradient title + "made by @uekv"
    print_gradient_line(" " * 28 + "made by @uekv", RED_DARK, RED_LIGHT)
    print()

    # Big ASCII art with slight gradient per line (darker top → lighter bottom)
    colors = [RED_DARK, RED_DARK, RED_MEDIUM, RED_MEDIUM, RED_MEDIUM,
              RED_LIGHT, RED_LIGHT, RED_LIGHT, RED_LIGHT]
    for i, line in enumerate(ascii_art):
        color = colors[min(i, len(colors)-1)]
        print(f"{color}{line}{RESET}")

    print()

    # The "PAID TOOL" / logo text
    logo = [
        "   ██████  ██ ▄█▀ ██▓▓█████▄ ",
        "▒██    ▒  ██▄█▒ ▓██▒▒██▀ ██▌",
        "░ ▓██▄   ▓███▄░ ▒██▒░██   █▌",
        "  ▒   ██▒▓██ █▄ ░██░░▓█▄   ▌",
        "▒██████▒▒▒██▒ █▄░██░░▒████▓ ",
        "▒ ▒▓▒ ▒ ░▒ ▒▒ ▓▒░▓   ▒▒▓  ▒ ",
        "░ ░▒  ░ ░░ ░▒ ▒░ ▒ ░ ░ ▒  ▒ ",
        "░  ░  ░  ░ ░░ ░  ▒ ░ ░ ░  ░ ",
        "      ░  ░  ░    ░     ░    ",
        "                     ░      "
    ]
    for line in logo:
        print_gradient_line(line.center(80), RED_MEDIUM, RED_LIGHT)

    print(f"\n{RED_DARK}{'─' * 80}{RESET}\n")

    # License input prompt
    while True:
        try:
            key = input(f"{BOLD}{RED_LIGHT}[+] enter your license > {RESET}")
            key = key.strip()

            if not key:
                print(f"{RED_MEDIUM}[-] empty key. try again.{RESET}")
                continue

            # ────────────────────────────────
            #   PUT YOUR REAL KEY CHECK HERE
            # ────────────────────────────────
            # For now just a placeholder — replace with your actual validation
            if key == "DEV-TEST-1234":
                print(f"\n{BOLD}{RED_LIGHT}[√] license accepted. tool unlocked.{RESET}\n")
                # → here you would start your real program / RAT / whatever
                time.sleep(1.5)
                break
            else:
                print(f"{RED_MEDIUM}[-] invalid license. try again.{RESET}")

        except KeyboardInterrupt:
            print(f"\n{RED_DARK}[!] goodbye.{RESET}")
            sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n{RED_DARK}[!] error: {e}{RESET}")
        time.sleep(3)
