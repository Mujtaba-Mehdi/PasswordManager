import tkinter as tk
from tkinter import messagebox, filedialog
from cryptography.fernet import Fernet

# Generate a key for encryption
key = Fernet.generate_key()
cipher_suite = Fernet(key)

# Create the main window
root = tk.Tk()
root.title("Password Manager")

# Create the labels and input fields
website_label = tk.Label(root, text="Website:", font=("Helvetica", 14))
website_entry = tk.Entry(root, width=30, borderwidth=2)

username_label = tk.Label(root, text="Username:", font=("Helvetica", 14))
username_entry = tk.Entry(root, width=30, borderwidth=2)

password_label = tk.Label(root, text="Password:", font=("Helvetica", 14))
password_entry = tk.Entry(root, show="*", width=30, borderwidth=2)

# Create the "Add Password" button
add_button = tk.Button(root, text="Add Password", padx=10, pady=5, fg="white", bg="#0072C6", font=("Helvetica", 14))

# Create the "Edit Password" button
edit_button = tk.Button(root, text="Edit Password", padx=10, pady=5, fg="white", bg="#0072C6", font=("Helvetica", 14))

# Create the "Delete Password" button
delete_button = tk.Button(root, text="Delete Password", padx=10, pady=5, fg="white", bg="#0072C6", font=("Helvetica", 14))

# Create the "Save Passwords" button
save_button = tk.Button(root, text="Save Passwords", padx=10, pady=5, fg="white", bg="#0072C6", font=("Helvetica", 14))

# Create the "Load Passwords" button
load_button = tk.Button(root, text="Load Passwords", padx=10, pady=5, fg="white", bg="#0072C6", font=("Helvetica", 14))

# Create the password listbox
password_listbox = tk.Listbox(root, width=60, font=("Helvetica", 12), borderwidth=2)
password_listbox.grid(row=4, columnspan=2, padx=10, pady=10)

# Set up grid layout
root.columnconfigure(0, weight=1)
root.columnconfigure(1, weight=1)
root.rowconfigure(4, weight=1)

website_label.grid(row=0, column=0, padx=10, pady=10)
website_entry.grid(row=0, column=1, padx=10, pady=10)

username_label.grid(row=1, column=0, padx=10, pady=10)
username_entry.grid(row=1, column=1, padx=10, pady=10)

password_label.grid(row=2, column=0, padx=10, pady=10)
password_entry.grid(row=2, column=1, padx=10, pady=10)

add_button.grid(row=3, column=0, padx=10, pady=10)
edit_button.grid(row=3, column=1, padx=10, pady=10)
delete_button.grid(row=3, column=2, padx=10, pady=10)
save_button.grid(row=3, column=3, padx=5, pady=5)
load_button.grid(row=3, column=4, padx=5, pady=5)


# Define function to add password to listbox
def add_password():
    website = website_entry.get()
    username = username_entry.get()
    password = password_entry.get().encode()

    # Check if any of the fields are empty
    if not website or not username or not password:
        messagebox.showerror("Error", "Please fill in all the fields.")
        return

    encrypted_password = cipher_suite.encrypt(password)
    password_listbox.insert(tk.END, f"Website: {website}  Username: {username}  Password: {encrypted_password.decode()}")
    website_entry.delete(0, tk.END)
    username_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)

add_button.config(command=add_password)


def edit_password():
    # Get the selected item from the listbox
    selected_item = password_listbox.curselection()
    if not selected_item:
        messagebox.showerror("Error", "Please select a password to edit.")
        return
    selected_password = password_listbox.get(selected_item[0])
    website, username, encrypted_password = selected_password.split("  ")
    website = website.split("Website: ")[1]
    username = username.split("Username: ")[1]
    # Extract the encrypted password from the selected password string
    encrypted_password = encrypted_password.split("Password: ")[1]
    print(f"Encrypted password: {encrypted_password}")

    # Decrypt the password
    try:
        decrypted_password = cipher_suite.decrypt(encrypted_password)
    except Exception as e:
        print(f"Error decrypting password: {e}")
        return

    # Create a new window for editing the password
    edit_window = tk.Toplevel(root)
    edit_window.title("Edit Password")

    # Create the labels and input fields
    website_label = tk.Label(edit_window, text="Website:", font=("Helvetica", 14))
    website_entry = tk.Entry(edit_window, width=30, borderwidth=2)
    website_entry.insert(0, website)

    username_label = tk.Label(edit_window, text="Username:", font=("Helvetica", 14))
    username_entry = tk.Entry(edit_window, width=30, borderwidth=2)
    username_entry.insert(0, username)

    password_label = tk.Label(edit_window, text="Password:", font=("Helvetica", 14))
    password_entry = tk.Entry(edit_window, width=30, borderwidth=2)
    password_entry.insert(0, decrypted_password)

    # Create the "Save" button
    save_button = tk.Button(edit_window, text="Save", padx=10, pady=5, fg="white", bg="#0072C6", font=("Helvetica", 14))

    # Set up grid layout
    edit_window.columnconfigure(0, weight=1)
    edit_window.columnconfigure(1, weight=1)
    edit_window.rowconfigure(3, weight=1)

    website_label.grid(row=0, column=0, padx=10, pady=10)
    website_entry.grid(row=0, column=1, padx=10, pady=10)

    username_label.grid(row=1, column=0, padx=10, pady=10)
    username_entry.grid(row=1, column=1, padx=10, pady=10)

    password_label.grid(row=2, column=0, padx=10, pady=10)
    password_entry.grid(row=2, column=1, padx=10, pady=10)

    save_button.grid(row=3, column=0, columnspan=2, padx=10, pady=10)

    # Define function to save edited password
    def save_edited_password():
        website = website_entry.get()
        username = username_entry.get()
        password = password_entry.get().encode()

        # Check if any of the fields are empty
        if not website or not username or not password:
            messagebox.showerror("Error", "Please fill in all the fields.")
            return

        encrypted_password = cipher_suite.encrypt(password)
        new_password = f"Website: {website}  Username: {username}  Password: {encrypted_password.decode()}"
        password_listbox.delete(selected_item)
        password_listbox.insert(selected_item, new_password)
        edit_window.destroy()

    save_button.config(command=save_edited_password)

edit_button.config(command=edit_password)


# Define function to delete password from listbox
def delete_password():
    # Get the selected item from the listbox
    selected_item = password_listbox.curselection()
    if not selected_item:
        messagebox.showerror("Error", "Please select a password to delete.")
        return
    password_listbox.delete(selected_item)
    # Update the file where you are storing the passwords
    with open("passwords.txt", "w") as f:
        for password in password_listbox.get(0, tk.END):
            f.write(f"{password}\n")

delete_button.config(command=delete_password)


def save_passwords():
    # Get the filename to save to
    filename = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])

    if filename:
        # Open the file and write each password in the listbox
        with open(filename, "wb") as f:
            for password in password_listbox.get(0, tk.END):
                password_components = password.split("Password: ")
                if len(password_components) == 2:
                    website_username, encrypted_password = password_components

                    website_username_components = website_username.split("Username: ")
                    if len(website_username_components) == 2:
                        website, username = website_username_components

                        f.write(website.encode() + "\n".encode())
                        f.write("Username: ".encode() + username.encode() + "\n".encode())
                        f.write("Password: ".encode() + encrypted_password.encode() + "\n".encode())
                        f.write("\n".encode())  # Add a new line after every entry

        messagebox.showinfo("Password Manager", "Passwords saved successfully.")

        # Update the file where you are storing the passwords
        with open("passwords.txt", "w") as f:
            for password in password_listbox.get(0, tk.END):
                f.write(f"{password}\n")


save_button.config(command=save_passwords)


def load_passwords():
    # Get the filename to load from
    filename = filedialog.askopenfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])

    if filename:
        # Clear the current passwords in the listbox
        password_listbox.delete(0, tk.END)

        # Open the file and read the passwords
        with open(filename, "rb") as f:
            current_password = {}
            for line in f:
                line = line.strip().decode()
                if line.startswith("Website: "):
                    current_password["website"] = line.split("Website: ")[1]
                elif line.startswith("Username: "):
                    current_password["username"] = line.split("Username: ")[1]
                elif line.startswith("Password: "):
                    current_password["encrypted_password"] = line.split("Password: ")[1]
                elif not line:
                    # Add the current password to the listbox and reset the current_password dict
                    password_string = f"Website: {current_password['website']}  Username: {current_password['username']}  Password: {current_password['encrypted_password']}"
                    password_listbox.insert(tk.END, password_string)
                    current_password = {}
                else:
                    # Invalid line format
                    print(f"Invalid line in password file: {line}")

        # If there is a partially loaded password remaining, add it to the listbox
        if current_password:
            password_string = f"Website: {current_password['website']}  Username: {current_password['username']}  Password: {current_password['encrypted_password']}"
            password_listbox.insert(tk.END, password_string)

        messagebox.showinfo("Password Manager", "Passwords loaded successfully.")

load_button.config(command=load_passwords)


# Define function to show password when selected in listbox
def show_password(event):
    # Get the selected item from the listbox
    selected_item = password_listbox.get(password_listbox.curselection())

    # Extract the encrypted password from the selected item
    encrypted_password = selected_item.split("Password: ")[1].encode()

#Bind the listbox to the show_password function
password_listbox.bind("<<ListboxSelect>>", show_password)

root.mainloop()