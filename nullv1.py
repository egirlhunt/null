#!/usr/bin/env python3
import sys
import time
import os
from colorama import init, Fore, Style

init(autoreset=True)

def display_gradient_ascii():
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
    
    # Create actual gradient with ANSI escape codes (256 color mode)
    gradient_colors = [
        "\033[38;5;196m",  # Bright Red
        "\033[38;5;196m",
        "\033[38;5;160m",  # Red
        "\033[38;5;160m",
        "\033[38;5;124m",  # Dark Red
        "\033[38;5;124m",
        "\033[38;5;160m",
        "\033[38;5;160m",
        "\033[38;5;196m",
        "\033[38;5;196m",
        "\033[38;5;160m",
        "\033[38;5;160m",
        "\033[38;5;124m",
        "\033[38;5;124m",
        "\033[38;5;160m",
        "\033[38;5;160m",
        "\033[38;5;196m",
        "\033[38;5;196m",
        "\033[38;5;160m"
    ]
    
    reset = "\033[0m"
    
    print("\n" * 2)
    
    # Display graphic art with gradient
    for i, line in enumerate(ascii_graphic):
        if i < len(gradient_colors):
            color = gradient_colors[i]
        else:
            color = "\033[38;5;160m"
        print(f"{color}{line}{reset}")
    
    print("\n")
    
    # Display text art with gradient
    for i, line in enumerate(ascii_text):
        if i < len(gradient_colors):
            color = gradient_colors[i]
        else:
            color = "\033[38;5;160m"
        print(f"{color}{line}{reset}")
    
    print("\n")
    
    # Add "made by @uekv on discord" on top
    print(f"{Fore.LIGHTRED_EX}made by @uekv on discord{Style.RESET_ALL}")
    print("\n" + "-" * 50)  # Regular dashes, not in []
    
    # Keep the license prompt format with [] and >
    print(f"\n{Fore.RED}[+]{Style.RESET_ALL} {Fore.WHITE}Enter License Key > {Style.RESET_ALL}", end="")

def validate_license_key():
    valid_key = "NULL-VIP-2024"
    user_key = input().strip()
    
    if user_key == valid_key:
        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}License Validated!{Style.RESET_ALL}")
        print("\n" + "-" * 50)  # Regular dashes
        return True
    else:
        print(f"\n{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Invalid License Key!{Style.RESET_ALL}")
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Tool closing in 3 seconds...{Style.RESET_ALL}")
        
        for i in range(3, 0, -1):
            print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Closing in {i}...{Style.RESET_ALL}")
            time.sleep(1)
        
        return False

def main():
    os.system('cls' if os.name == 'nt' else 'clear')
    display_gradient_ascii()
    
    if not validate_license_key():
        sys.exit(1)
    
    # Main menu
    print(f"\n{Fore.RED}[1]{Style.RESET_ALL} {Fore.WHITE}Start{Style.RESET_ALL}")
    print(f"{Fore.RED}[2]{Style.RESET_ALL} {Fore.WHITE}Settings{Style.RESET_ALL}")
    print(f"{Fore.RED}[3]{Style.RESET_ALL} {Fore.WHITE}Exit{Style.RESET_ALL}")
    
    print("\n" + "-" * 50)  # Regular dashes
    
    choice = input(f"\n{Fore.RED}[+]{Style.RESET_ALL} {Fore.WHITE}Select > {Style.RESET_ALL}")
    
    if choice == "1":
        print(f"\n{Fore.GREEN}[+]{Style.RESET_ALL} {Fore.GREEN}Starting...{Style.RESET_ALL}")
        time.sleep(2)
    elif choice == "3":
        print(f"\n{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Exiting...{Style.RESET_ALL}")
        time.sleep(1)
        sys.exit(0)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Interrupted{Style.RESET_ALL}")
        sys.exit(0)
