import tkinter as tk
from tkinter import messagebox, simpledialog
import main  #import your main.py module
import os

#load pass from terminal vvvvvv
#main.masterPassword = main.setupMasterPassword()
#main.loadData()

def loginScreen():
    loginWin = tk.Tk()
    loginWin.title("Login - RSA Password Manager")
    loginWin.geometry("400x200")
    
    tk.Label(loginWin, text="Enter Master Password").pack(pady=20)
    pwdEntry = tk.Entry(loginWin, show="*")
    pwdEntry.pack(pady=5)
    
    def attemptLogin():
        password = pwdEntry.get()
        if not os.path.exists("master.hash"):
            # Create new master password
            main.masterPassword = password
            hashed = main.hashlib.sha256(password.encode()).hexdigest()
            with open("master.hash", "w") as f:
                f.write(hashed)
            messagebox.showinfo("Welcome", "Master password created!")
            loginWin.destroy()
            main.loadData()
            mainMenu()
        else:
            #existing password verification
            with open("master.hash", "r") as f:
                savedHash = f.read()
            if main.hashlib.sha256(password.encode()).hexdigest() == savedHash:
                main.masterPassword = password
                messagebox.showinfo("Welcome", "Login successful!")
                loginWin.destroy()
                main.loadData()
                mainMenu()
            else:
                messagebox.showerror("Error", "Login attempt unsuccessful")

    tk.Button(loginWin, text="Login", command=attemptLogin).pack(pady=15)
    loginWin.mainloop()





def addPasswordGUI():
    web = simpledialog.askstring("Website", "Enter website domain:")
    user = simpledialog.askstring("Username", "Enter your username:")
    pwd = simpledialog.askstring("Password", "Enter your password:", show="*")
    
    if web and user and pwd:
        cipherb64 = main.encryptWithPublic(pwd)
        main.passwordData[web] = {"Username": user, "Password": cipherb64}
        main.saveData()
        messagebox.showinfo("Success", f"Password for {web} added!")
    else:
        messagebox.showwarning("Input Error", "All fields are required.")


def viewPasswordGUI():
    if not main.passwordData:
        messagebox.showinfo("No Data", "No passwords saved yet!")
        return
    
    webs = sorted(main.passwordData.keys())
    site_choice = simpledialog.askinteger("View Password",
                                          "Select website number:\n" +
                                          "\n".join([f"{i+1}. {w}" for i, w in enumerate(webs)]))
    if site_choice and 1 <= site_choice <= len(webs):
        selectedSite = webs[site_choice-1]
        details = main.passwordData[selectedSite]
        decryptedPwd = main.decryptWithPrivate(details["Password"], main.masterPassword)
        messagebox.showinfo(f"{selectedSite}",
                            f"Username: {details['Username']}\nPassword: {decryptedPwd}")
    else:
        messagebox.showwarning("Invalid Choice", "Please select a valid website number.")


def remPasswordGUI():
    if not main.passwordData:
        messagebox.showinfo("No Data", "No passwords saved yet!")
        return
    
    webs = sorted(main.passwordData.keys())
    site_choice = simpledialog.askinteger("Remove Password",
                                          "Select website number:\n" +
                                          "\n".join([f"{i+1}. {w}" for i, w in enumerate(webs)]))
    if site_choice and 1 <= site_choice <= len(webs):
        selectedSite = webs[site_choice-1]
        main.passwordData.pop(selectedSite)
        main.saveData()
        messagebox.showinfo("Removed", f"Password for {selectedSite} removed!")
    else:
        messagebox.showwarning("Invalid Choice", "Please select a valid website number.")


def updPasswordGUI():
    if not main.passwordData:
        messagebox.showinfo("No Data", "No passwords saved yet!")
        return
    
    webs = sorted(main.passwordData.keys())
    site_choice = simpledialog.askinteger("Update Password",
                                          "Select website number:\n" +
                                          "\n".join([f"{i+1}. {w}" for i, w in enumerate(webs)]))
    if site_choice and 1 <= site_choice <= len(webs):
        selectedSite = webs[site_choice-1]
        newPwd = simpledialog.askstring("New Password", "Enter new password:", show="*")
        if newPwd:
            cipherb64 = main.encryptWithPublic(newPwd)
            main.passwordData[selectedSite]["Password"] = cipherb64
            main.saveData()
            messagebox.showinfo("Updated", f"Password for {selectedSite} updated!")
        else:
            messagebox.showwarning("Input Error", "Password cannot be empty.")
    else:
        messagebox.showwarning("Invalid Choice", "Please select a valid website number.")


def searchPasswordGUI():
    if not main.passwordData:
        messagebox.showinfo("No Data", "No passwords saved yet!")
        return
    
    query = simpledialog.askstring("Search", "Enter website name to search:")
    if query:
        matches = [w for w in main.passwordData if query.lower() in w.lower()]
        if not matches:
            messagebox.showinfo("No Match", "No websites found matching your query.")
            return
        site_choice = simpledialog.askinteger("Select Website",
                                              "Matching websites:\n" +
                                              "\n".join([f"{i+1}. {w}" for i, w in enumerate(matches)]))
        if site_choice and 1 <= site_choice <= len(matches):
            selectedSite = matches[site_choice-1]
            details = main.passwordData[selectedSite]
            decryptedPwd = main.decryptWithPrivate(details["Password"], main.masterPassword)
            messagebox.showinfo(f"{selectedSite}",
                                f"Username: {details['Username']}\nPassword: {decryptedPwd}")
        else:
            messagebox.showwarning("Invalid Choice", "Please select a valid website number.")


def genPasswordGUI():
    length = simpledialog.askinteger("Password Length", "Enter password length (5-25):")
    if length:
        newPwd = main.generatePassword(length)
        messagebox.showinfo("Generated Password", f"Password: {newPwd}")
    else:
        messagebox.showwarning("Input Error", "Invalid length.")


def mainMenu():
    root = tk.Tk()
    root.title("Basic RSA Password Manager")
    root.geometry("400x400")

    tk.Label(root, text="Basic RSA Password Manager", font=("Arial", 16)).pack(pady=10)
    
    tk.Button(root, text="Add Password", width=25, command=addPasswordGUI).pack(pady=5)
    tk.Button(root, text="View Password", width=25, command=viewPasswordGUI).pack(pady=5)
    tk.Button(root, text="Remove Password", width=25, command=remPasswordGUI).pack(pady=5)
    tk.Button(root, text="Update Password", width=25, command=updPasswordGUI).pack(pady=5)
    tk.Button(root, text="Search Password", width=25, command=searchPasswordGUI).pack(pady=5)
    tk.Button(root, text="Generate Password", width=25, command=genPasswordGUI).pack(pady=5)
    tk.Button(root, text="Quit", width=25, command=root.quit).pack(pady=20)

    root.mainloop()


if __name__ == "__main__":
    if hasattr(main, 'masterPassword'):
        main.loadData()
    else:
        main.masterPassword = None
    loginScreen()
