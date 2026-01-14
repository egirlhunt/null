#!/usr/bin/env python3
import sys
import time
import os
from colorama import init, Fore, Style

# Initialize colorama for Windows compatibility
init(autoreset=True)

def display_gradient_ascii():
    """Display both ASCII arts with gradient red colors"""
    # First ASCII art (text)
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
    
    # Second ASCII art (graphic)
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
    
    # Red gradient colors (darker to lighter and back)
    colors = [
        Fore.LIGHTRED_EX,
        Fore.LIGHTRED_EX,
        Fore.RED,
        Fore.RED,
        Fore.DARK_RED,
        Fore.RED,
        Fore.RED,
        Fore.LIGHTRED_EX,
        Fore.LIGHTRED_EX,
        Fore.RED,
        Fore.RED,
        Fore.DARK_RED,
        Fore.RED,
        Fore.RED,
        Fore.LIGHTRED_EX,
        Fore.LIGHTRED_EX,
        Fore.RED,
        Fore.RED,
        Fore.DARK_RED,
        Fore.RED
    ]
    
    print("\n" * 2)
    
    # Display graphic art
    for i, line in enumerate(ascii_graphic):
        if i < len(colors):
            color = colors[i]
        else:
            color = Fore.RED
        print(f"{color}{line}{Style.RESET_ALL}")
    
    print("\n" * 1)
    
    # Display text art
    for i, line in enumerate(ascii_text):
        if i < len(colors):
            color = colors[i]
        else:
            color = Fore.RED
        print(f"{color}{line}{Style.RESET_ALL}")
    
    print("\n" * 1)
    
    # Display tool info with [+] [-] indicators
    print(f"{Fore.LIGHTRED_EX}[+]{Style.RESET_ALL} {Fore.LIGHTWHITE_EX}NULL Tool v1.0{Style.RESET_ALL}")
    print(f"{Fore.LIGHTRED_EX}[+]{Style.RESET_ALL} {Fore.LIGHTWHITE_EX}Developed by: NULL Team{Style.RESET_ALL}")
    print(f"{Fore.LIGHTRED_EX}[+]{Style.RESET_ALL} {Fore.LIGHTWHITE_EX}License Required: VIP{Style.RESET_ALL}")
    print(f"{Fore.LIGHTRED_EX}[-]{Style.RESET_ALL}" * 40 + f"{Style.RESET_ALL}")

def validate_license_key():
    """Validate the license key entered by user"""
    # Your actual license key (change this to your desired key)
    valid_key = "NULL-VIP-2024"
    
    print(f"{Fore.LIGHTRED_EX}[+]{Style.RESET_ALL} {Fore.LIGHTWHITE_EX}Enter License Key: {Style.RESET_ALL}", end="")
    user_key = input().strip()
    
    if user_key == valid_key:
        print(f"\n{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} {Fore.LIGHTGREEN_EX}License Validated Successfully!{Style.RESET_ALL}")
        print(f"{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} {Fore.LIGHTGREEN_EX}Welcome to NULL Tool v1.0{Style.RESET_ALL}")
        return True
    else:
        print(f"\n{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Invalid License Key!{Style.RESET_ALL}")
        print(f"{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Tool closing in 3 seconds...{Style.RESET_ALL}")
        
        # Countdown timer
        for i in range(3, 0, -1):
            print(f"{Fore.RED}[!]{Style.RESET_ALL} {Fore.RED}Closing in {i}...{Style.RESET_ALL}")
            time.sleep(1)
        
        return False

def main_menu():
    """Main menu after successful license validation"""
    print(f"\n{Fore.LIGHTRED_EX}[+]{Style.RESET_ALL} {Fore.LIGHTWHITE_EX}Main Menu{Style.RESET_ALL}")
    print(f"{Fore.LIGHTRED_EX}[-]{Style.RESET_ALL}" * 40)
    print(f"{Fore.LIGHTRED_EX}[1]{Style.RESET_ALL} {Fore.LIGHTWHITE_EX}Start Scanning{Style.RESET_ALL}")
    print(f"{Fore.LIGHTRED_EX}[2]{Style.RESET_ALL} {Fore.LIGHTWHITE_EX}Configure Settings{Style.RESET_ALL}")
    print(f"{Fore.LIGHTRED_EX}[3]{Style.RESET_ALL} {Fore.LIGHTWHITE_EX}View Logs{Style.RESET_ALL}")
    print(f"{Fore.LIGHTRED_EX}[4]{Style.RESET_ALL} {Fore.LIGHTWHITE_EX}Exit{Style.RESET_ALL}")
    print(f"{Fore.LIGHTRED_EX}[-]{Style.RESET_ALL}" * 40)
    
    choice = input(f"{Fore.LIGHTRED_EX}[+]{Style.RESET_ALL} {Fore.LIGHTWHITE_EX}Select option: {Style.RESET_ALL}")
    return choice

def main():
    """Main function"""
    # Clear screen
    os.system('cls' if os.name == 'nt' else 'clear')
    
    # Display ASCII art
    display_gradient_ascii()
    
    # Validate license
    if not validate_license_key():
        sys.exit(1)  # Exit if license is invalid
    
    # Main program loop
    while True:
        choice = main_menu()
        
        if choice == "1":
            print(f"\n{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} {Fore.LIGHTGREEN_EX}Starting scan...{Style.RESET_ALL}")
            # Add your scanning functionality here
            time.sleep(2)
        elif choice == "2":
            print(f"\n{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} {Fore.LIGHTGREEN_EX}Opening settings...{Style.RESET_ALL}")
            # Add your settings functionality here
            time.sleep(2)
        elif choice == "3":
            print(f"\n{Fore.LIGHTGREEN_EX}[+]{Style.RESET_ALL} {Fore.LIGHTGREEN_EX}Displaying logs...{Style.RESET_ALL}")
            # Add your log viewing functionality here
            time.sleep(2)
        elif choice == "4":
            print(f"\n{Fore.LIGHTRED_EX}[-]{Style.RESET_ALL} {Fore.LIGHTRED_EX}Exiting NULL Tool...{Style.RESET_ALL}")
            time.sleep(1)
            break
        else:
            print(f"\n{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Invalid option!{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n\n{Fore.RED}[-]{Style.RESET_ALL} {Fore.RED}Interrupted by user{Style.RESET_ALL}")
        sys.exit(0)
