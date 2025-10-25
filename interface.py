import os

line = "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
banner = """
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃                                                                   ┃
┃                      ⠀⠀⠀⠀⠀⠀⠀⠀⢀⣠⣤⣤⣶⣶⣶⣶⣤⣤⣄⡀          ⠀⠀⠀⠀⠀⠀  ⠀      ┃
┃                      ⠀⠀⠀⠀⢀⣴⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⡀          ⠀⠀⠀⠀         ┃
┃                      ⠀⠀⢀⣴⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀                   ┃
┃                      ⠀⢀⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⡀⠀                   ┃
┃                      ⠀⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠟⢿⣿⣿⣿⣿⣿⣿⡿⣿⣿⣿⣿⣿⠀                   ┃
┃                      ⢰⣿⣿⣿⣿⣿⣿⣿⣿⠟⠁⠀⠀⠙⠿⠿⠛⠉⣠⣾⣿⣿⣿⣿⣿⡆                   ┃
┃                      ⢸⣿⣿⣿⣿⣿⣿⠟⠁⢀⣠⣄⠀⠀⠀⠀⣠⣾⣿⣿⣿⣿⣿⣿⣿⡇                   ┃
┃                      ⠈⣿⣿⣿⣿⣟⣥⣶⣾⣿⣿⣿⣷⣦⣠⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⠁                   ┃
┃                      ⠀⠹⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀                   ┃
┃                      ⠀⠀⠙⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠋⠀⠀                   ┃
┃                      ⠀⠀⠀⠈⢻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠁⠀⠀⠀                   ┃
┃                      ⠀⠀⠀⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⠿⠛⠉⠀⠀⠀⠀⠀⠀                   ┃
┃                      ⠀⠀⠀⠀⢸⡿⠛⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀                   ┃
┃                                                                   ┃"""

class ConsoleMenu:
    def __init__(self):
        self.appname = "★彡━━━━━━ ★ W E L C O M E ★ T O ★ M E S S E N G E R ★ ━━━━━━彡★"
        self.sessions = {"Handshake": "Session handshake: Establishing handshake and trust", 
                              "Chat": "Session chat: Trust is verified, start chat session"}
        self.options = [
            "1. Generate your RSA key",
            "2. Get public key certificate",
            "3. Handshake (public key certificate exchange)",
            "4. Check certificate reliability"
        ]
        self.current_selection = 0
        self.title_enter_msg = "Enter message to send (or 'exit' to quit): "

    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def session_handshake_menu(self):
        menu_width = len(self.appname) + 6

        print()
        print("\033[32m" + banner + "\033[0m")
        print("\033[32m" + "┣" + "━" * menu_width + "┫" + "\033[0m")
        print("\033[32m" + "┃  " + self.appname + "  ┃" + "\033[0m")
        print("\033[32m" + "┣" + "━" * menu_width + "┫" + "\033[0m")
        spaces = menu_width - len(self.sessions['Handshake'])
        spaces_left, spaces_right = spaces // 2, spaces - spaces // 2
        print("\033[32m" + f"┃{' ' * spaces_left}{self.sessions['Handshake']}{' ' * spaces_right}┃" + "\033[0m")
        print("\033[32m" + "┣" + "━" * menu_width + "┫" + "\033[0m")

        for i, option in enumerate(self.options):
            prefix = "-> " if i == self.current_selection else "   "
            option_text = f"{prefix}{option}"
            spaces = menu_width - len(option_text)
            print("\033[32m" + f"┃{option_text}{' ' * spaces}┃" + "\033[0m")

        print("\033[32m" + "┣" + "━" * menu_width + "┫" + "\033[0m")
        footer = "↑↓ Переключить пункт • Enter Подтвердить"
        padding = (menu_width - len(footer)) // 2
        print("\033[32m" + "┃" + " " * padding + footer + " " * padding + " ┃" + "\033[0m")
        print("\033[32m" + "┗" + "━" * menu_width + "┛" + "\033[0m")

    def session_chat_menu(self):
        menu_width = len(self.appname) + 6

        print()
        print("\033[32m" + banner + "\033[0m")
        print("\033[32m" + "┣" + "━" * menu_width + "┫" + "\033[0m")
        print("\033[32m" + "┃  " + self.appname + "  ┃" + "\033[0m")
        print("\033[32m" + "┣" + "━" * menu_width + "┫" + "\033[0m")
        spaces = menu_width - len(self.sessions['Handshake'])
        spaces_left, spaces_right = spaces // 2, spaces - spaces // 2
        print("\033[32m" + f"┃{' ' * spaces_left}{self.sessions['Chat']}{' ' * spaces_right}┃" + "\033[0m")
        print("\033[32m" + "┣" + "━" * menu_width + "┫" + "\033[0m")

        footer = "↩ Enter back to return to the session handshake"
        spaces = (menu_width - len(footer))
        spaces_left, spaces_right = spaces // 2, spaces - spaces // 2
        print("\033[32m" + "┃" + " " * spaces_left + footer + " " * spaces_right + "┃" + "\033[0m")
        print("\033[32m" + "┗" + "━" * menu_width + "┛" + "\033[0m")

    def draw_console(self, session: int = 1, buffer=None):
        if session == 1:
            self.session_handshake_menu()
        else:
            self.session_chat_menu()
        if buffer:
            print("\033[32m" + buffer + "\033[0m")

if __name__ == '__main__':
    menu = ConsoleMenu()
    menu.draw_console()