import tkinter as tk
from tkinter import simpledialog, messagebox
import json
import os
import re
import bcrypt

# Initialize user data
user_data_file = 'users.json'

if not os.path.exists(user_data_file):
    with open(user_data_file, 'w') as f:
        json.dump({
            "users": {
                "ADMIN": {
                    "password": bcrypt.hashpw("".encode(), bcrypt.gensalt()).decode(),
                    "blocked": False,
                    "password_restrictions": False
                }
            }
        }, f)

def load_user_data():
    with open(user_data_file, 'r') as f:
        return json.load(f)

def save_user_data(data):
    with open(user_data_file, 'w') as f:
        json.dump(data, f)

class UserManagementApp:
    def __init__(self, root):
        self.root = root
        self.root.title("User Management App") 
        self.current_user = None
        self.login_attempts = 0
        self.create_menu()
        self.create_login_interface()

    def create_menu(self):
        menu = tk.Menu(self.root)
        self.root.config(menu=menu)
        file_menu = tk.Menu(menu)
        menu.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Exit", command=self.root.quit)
        help_menu = tk.Menu(menu)
        menu.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="About", command=self.show_about)

    def create_login_interface(self):
        self.login_frame = tk.Frame(self.root)
        self.login_frame.pack(padx=10, pady=10)
        tk.Label(self.login_frame, text="Username:").grid(row=0, column=0, padx=5, pady=5)
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.grid(row=0, column=1, padx=5, pady=5)
        tk.Label(self.login_frame, text="Password:").grid(row=1, column=0, padx=5, pady=5)
        self.password_entry = tk.Entry(self.login_frame, show='*')
        self.password_entry.grid(row=1, column=1, padx=5, pady=5)
        self.login_button = tk.Button(self.login_frame, text="Login", command=self.login)
        self.login_button.grid(row=2, column=0, columnspan=2, pady=10)

    def disable_login(self, seconds):
        self.login_button.config(state=tk.DISABLED)
        self.root.after(seconds * 1000, self.enable_login)

    def enable_login(self):
        self.login_button.config(state=tk.NORMAL)

    def login(self):
        username = self.username_entry.get()
        password = self.password_entry.get()
        if not username:
            messagebox.showerror("Error", "Please enter a username!")
            return
        user_data = load_user_data()
        users = user_data["users"]
        if username not in users:
            self.login_attempts += 1
            messagebox.showerror("Error", "User not found!")
        elif users[username]["blocked"]:
            self.login_attempts += 1
            messagebox.showerror("Error", "User is blocked!")
        elif not bcrypt.checkpw(password.encode(), users[username]["password"].encode()):
            self.login_attempts += 1
            if self.login_attempts == 1:
                messagebox.showwarning("Warning", "Incorrect password! Please wait 5 seconds before the next attempt.")
                self.disable_login(5)
            elif self.login_attempts == 2:
                messagebox.showwarning("Warning", "Incorrect password! Please wait 10 seconds before the next attempt.")
                self.disable_login(10)
            else:
                messagebox.showerror("Error", "Too many incorrect attempts. The application will now exit.")
                self.root.quit()
        else:
            self.current_user = username
            self.login_attempts = 0
            self.show_user_interface()

    def show_user_interface(self):
        self.login_frame.destroy()
        if self.current_user == "ADMIN":
            self.show_admin_interface()
        else:
            self.show_user_options()

    def show_admin_interface(self):
        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack(padx=10, pady=10)
        button_font = ('Arial', 12, 'bold')
        button_width = 25
        tk.Button(self.main_frame, text="Change Admin Password", command=self.change_admin_password, font=button_font, width=button_width).pack(pady=5)
        tk.Button(self.main_frame, text="View Users", command=self.view_users, font=button_font, width=button_width).pack(pady=5)
        tk.Button(self.main_frame, text="Add User", command=self.add_user, font=button_font, width=button_width).pack(pady=5)
        tk.Button(self.main_frame, text="Block User", command=self.block_user, font=button_font, width=button_width).pack(pady=5)
        tk.Button(self.main_frame, text="Toggle Password Restrictions", command=self.toggle_password_restrictions, font=button_font, width=button_width).pack(pady=5)
        tk.Button(self.main_frame, text="Logout", command=self.logout, font=button_font, width=button_width).pack(pady=5)

    def show_user_options(self):
        self.main_frame = tk.Frame(self.root)
        self.main_frame.pack(padx=10, pady=10)
        button_width = 25
        tk.Button(self.main_frame, text="Change Password", command=self.change_password, width=button_width).pack(pady=5)
        tk.Button(self.main_frame, text="Logout", command=self.logout, width=button_width).pack(pady=5)

    def change_admin_password(self):
        user_data = load_user_data()
        current_password = simpledialog.askstring("Change Admin Password", "Enter current password:", show='*')
        if not bcrypt.checkpw(current_password.encode(), user_data["users"]["ADMIN"]["password"].encode()):
            messagebox.showerror("Error", "Incorrect current password!")
            return
        new_password = simpledialog.askstring("Change Admin Password", "Enter new password:", show='*')
        confirm_password = simpledialog.askstring("Change Admin Password", "Confirm new password:", show='*')
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return
        hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        user_data["users"]["ADMIN"]["password"] = hashed
        save_user_data(user_data)
        messagebox.showinfo("Success", "Admin password changed successfully!")

    def view_users(self):
        user_data = load_user_data()
        users = user_data["users"]
        users_list = "\n".join([f"{user}: blocked={details['blocked']}, restrictions={details['password_restrictions']}" for user, details in users.items()])
        messagebox.showinfo("Users", users_list)

    def add_user(self):
        username = simpledialog.askstring("Add User", "Enter new username:")
        if not username:
            return
        user_data = load_user_data()
        if username in user_data["users"]:
            messagebox.showerror("Error", "User already exists!")
            return
        # Створити порожній хеш як тимчасовий пароль
        hashed = bcrypt.hashpw("".encode(), bcrypt.gensalt()).decode()
        user_data["users"][username] = {
            "password": hashed,
            "blocked": False,
            "password_restrictions": False
        }
        save_user_data(user_data)
        messagebox.showinfo("Success", "User added successfully!")

    def block_user(self):
        username = simpledialog.askstring("Block User", "Enter username to block:")
        if not username:
            return
        user_data = load_user_data()
        if username not in user_data["users"]:
            messagebox.showerror("Error", "User not found!")
            return
        user_data["users"][username]["blocked"] = True
        save_user_data(user_data)
        messagebox.showinfo("Success", "User blocked successfully!")

    def toggle_password_restrictions(self):
        username = simpledialog.askstring("Toggle Password Restrictions", "Enter username:")
        if not username:
            return
        user_data = load_user_data()
        if username not in user_data["users"]:
            messagebox.showerror("Error", "User not found!")
            return
        user_data["users"][username]["password_restrictions"] = not user_data["users"][username]["password_restrictions"]
        save_user_data(user_data)
        status = "enabled" if user_data["users"][username]["password_restrictions"] else "disabled"
        messagebox.showinfo("Success", f"Password restrictions {status} for user {username}.")

    def change_password(self):
        user_data = load_user_data()
        current_password = simpledialog.askstring("Change Password", "Enter current password:", show='*')
        if not bcrypt.checkpw(current_password.encode(), user_data["users"][self.current_user]["password"].encode()):
            messagebox.showerror("Error", "Incorrect current password!")
            return
        new_password = simpledialog.askstring("Change Password", "Enter new password:", show='*')
        confirm_password = simpledialog.askstring("Change Password", "Confirm new password:", show='*')
        if new_password != confirm_password:
            messagebox.showerror("Error", "Passwords do not match!")
            return
        if user_data["users"][self.current_user]["password_restrictions"]:
            if not re.search(r'[,.:;!?]', new_password):
                messagebox.showerror("Error", "Password must contain at least one punctuation mark!")
                return
            if not re.search(r'[0-9]', new_password):
                messagebox.showerror("Error", "Password must contain at least one digit!")
                return
            if not re.search(r'[\*\(\)\-\+\%=/]', new_password):
                messagebox.showerror("Error", "Password must contain at least one mathematical operator!")
                return
        hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        user_data["users"][self.current_user]["password"] = hashed
        save_user_data(user_data)
        messagebox.showinfo("Success", "Password changed successfully!")

    def logout(self):
        self.current_user = None
        self.main_frame.destroy()
        self.create_login_interface()

    def show_about(self):
        messagebox.showinfo("About", "Author: Prysievok Oksana\nVersion: 1.0\nTask: The presence of numbers, punctuation marks, and arithmetic operation signs. Additionally secure password hashing.")

if __name__ == "__main__":
    root = tk.Tk()
    app = UserManagementApp(root)
    root.mainloop()
