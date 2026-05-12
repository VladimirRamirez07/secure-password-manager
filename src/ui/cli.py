"""
CLI interface using Rich for beautiful terminal output.
Main interaction point for the user.
"""

from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich import box

from src.crypto.encryption import EncryptionManager
from src.crypto.master_password import MasterPasswordManager
from src.database.db import DatabaseManager
from src.utils.password_generator import PasswordGenerator
from src.utils.auto_lock import AutoLock


console = Console()


class CLI:

    def __init__(self):
        self.db       = DatabaseManager()
        self.enc      = EncryptionManager()
        self.gen      = PasswordGenerator()
        self.auto_lock = AutoLock(timeout=300)
        self.master   = None

    # ------------------------------------------------------------------ #
    #  Entry point                                                         #
    # ------------------------------------------------------------------ #

    def run(self) -> None:
        self.db.connect()
        self.master = MasterPasswordManager(self.db)

        console.print("\n[bold cyan]🔐 Secure Password Manager[/bold cyan]\n")

        if not self.master.is_vault_initialized():
            self._setup_vault()
        else:
            self._login()

        self.auto_lock.start(self._on_auto_lock)
        self._main_menu()

    # ------------------------------------------------------------------ #
    #  Auth                                                                #
    # ------------------------------------------------------------------ #

    def _setup_vault(self) -> None:
        console.print("[yellow]First run — create your master password.[/yellow]\n")
        while True:
            try:
                pwd  = Prompt.ask("[bold]Master password[/bold]", password=True)
                pwd2 = Prompt.ask("Confirm password", password=True)
                if pwd != pwd2:
                    console.print("[red]Passwords do not match.[/red]")
                    continue
                self.master.create_vault(pwd)
                console.print("[green]✓ Vault created successfully![/green]\n")
                break
            except ValueError as e:
                console.print(f"[red]{e}[/red]")

    def _login(self) -> None:
        attempts = 0
        while attempts < 3:
            pwd = Prompt.ask("[bold]Master password[/bold]", password=True)
            if self.master.unlock_vault(pwd):
                console.print("[green]✓ Vault unlocked.[/green]\n")
                return
            attempts += 1
            console.print(f"[red]Wrong password. {3 - attempts} attempt(s) left.[/red]")
        console.print("[bold red]Too many failed attempts. Exiting.[/bold red]")
        raise SystemExit(1)

    def _on_auto_lock(self) -> None:
        self.master.lock_vault()
        console.print("\n[yellow]⏱ Vault auto-locked due to inactivity.[/yellow]")

    # ------------------------------------------------------------------ #
    #  Main menu                                                           #
    # ------------------------------------------------------------------ #

    def _main_menu(self) -> None:
        options = {
            "1": ("List passwords",    self._list_entries),
            "2": ("Add password",      self._add_entry),
            "3": ("Delete password",   self._delete_entry),
            "4": ("Generate password", self._generate_password),
            "5": ("Lock vault",        self._manual_lock),
            "6": ("Exit",              self._exit),
        }

        while True:
            if not self.master.is_unlocked:
                console.print("[yellow]Vault is locked. Please login again.[/yellow]")
                self._login()

            self.auto_lock.reset()
            console.print(f"\n[dim]Auto-lock in {self.auto_lock.time_remaining}s[/dim]")

            for key, (label, _) in options.items():
                console.print(f"  [cyan]{key}[/cyan]. {label}")

            choice = Prompt.ask("\nOption", choices=list(options.keys()))
            options[choice][1]()

    # ------------------------------------------------------------------ #
    #  Actions                                                             #
    # ------------------------------------------------------------------ #

    def _list_entries(self) -> None:
        entries = self.db.get_all_entries()
        if not entries:
            console.print("[dim]No passwords saved yet.[/dim]")
            return

        key = self.master.get_session_key()
        table = Table(box=box.ROUNDED, show_header=True, header_style="bold cyan")
        table.add_column("ID",       width=5)
        table.add_column("Site",     width=20)
        table.add_column("Username", width=25)
        table.add_column("Password", width=30)

        for row in entries:
            password = self.enc.decrypt(key, row["password"], row["iv"])
            table.add_row(str(row["id"]), row["site"], row["username"], password)

        console.print(table)

    def _add_entry(self) -> None:
        site     = Prompt.ask("Site")
        username = Prompt.ask("Username")

        use_gen = Confirm.ask("Generate password automatically?")
        if use_gen:
            password = self.gen.generate()
            console.print(f"[green]Generated:[/green] {password}")
        else:
            password = Prompt.ask("Password", password=True)

        strength = self.gen.evaluate_strength(password)
        console.print(f"[dim]Strength: {strength['label']} ({strength['score']}/100)[/dim]")

        notes = Prompt.ask("Notes (optional)", default="")
        key   = self.master.get_session_key()
        ciphertext, nonce = self.enc.encrypt(key, password)

        entry_id = self.db.save_entry(site, username, ciphertext, nonce, b"", notes)
        console.print(f"[green]✓ Entry saved (ID: {entry_id})[/green]")

    def _delete_entry(self) -> None:
        self._list_entries()
        entry_id = int(Prompt.ask("ID to delete"))
        if Confirm.ask(f"Delete entry {entry_id}?"):
            self.db.delete_entry(entry_id)
            console.print("[green]✓ Entry deleted.[/green]")

    def _generate_password(self) -> None:
        try:
            length = int(Prompt.ask("Length", default="16"))
        except ValueError:
            console.print("[red]Please enter a valid number.[/red]")
            return

        if length < 8:
            console.print("[red]Minimum length is 8.[/red]")
            return

        pwd = self.gen.generate(length=length)
        strength = self.gen.evaluate_strength(pwd)
        console.print(f"\n[bold green]{pwd}[/bold green]")
        console.print(f"[dim]Strength: {strength['label']} ({strength['score']}/100)[/dim]")

    def _manual_lock(self) -> None:
        self.master.lock_vault()
        self.auto_lock.stop()
        console.print("[yellow]🔒 Vault locked.[/yellow]")

    def _exit(self) -> None:
        self.master.lock_vault()
        self.auto_lock.stop()
        self.db.close()
        console.print("[dim]Goodbye.[/dim]")
        raise SystemExit(0)