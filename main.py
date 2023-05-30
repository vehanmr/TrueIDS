import sys
import sqlite3
import bcrypt
from PyQt5 import QtWidgets, QtGui, QtCore
from home_page import *


# Class for the login form
class LoginPage(QtWidgets.QDialog):                                                                                                  
    def __init__(self, parent=None):
        super().__init__(parent)

        self.setWindowTitle("TrueIDS Login")
        self.setFixedSize(400, 300)
        self.setWindowIcon(QtGui.QIcon("logo.png"))

        layout = QtWidgets.QVBoxLayout()

        logo_label = QtWidgets.QLabel()
        logo_pixmap = QtGui.QPixmap("logo.png")
        scaled_logo_pixmap = logo_pixmap.scaled(80, 80, QtCore.Qt.KeepAspectRatio, QtCore.Qt.SmoothTransformation)
        logo_label.setPixmap(scaled_logo_pixmap)
        logo_label.setAlignment(QtCore.Qt.AlignCenter)
        layout.addWidget(logo_label)

        app_title_label = QtWidgets.QLabel("TrueIDS")
        app_title_label.setAlignment(QtCore.Qt.AlignCenter)
        app_title_label.setStyleSheet("font-size: 24px; font-weight: bold;")
        layout.addWidget(app_title_label)

        app_subtitle_label = QtWidgets.QLabel("Host-Based Intrusion Detection System")
        app_subtitle_label.setAlignment(QtCore.Qt.AlignCenter)
        app_subtitle_label.setStyleSheet("font-size: 14px; font-style: italic;")
        layout.addWidget(app_subtitle_label)

        self.username_label = QtWidgets.QLabel("Username:")
        layout.addWidget(self.username_label)
        self.username_input = QtWidgets.QLineEdit()
        layout.addWidget(self.username_input)

        self.password_label = QtWidgets.QLabel("Password:")
        layout.addWidget(self.password_label)
        self.password_input = QtWidgets.QLineEdit()
        self.password_input.setEchoMode(QtWidgets.QLineEdit.Password)
        layout.addWidget(self.password_input)

        self.login_button = QtWidgets.QPushButton("Login")
        self.login_button.clicked.connect(self.handle_login)
        layout.addWidget(self.login_button)

        self.setLayout(layout)


    # Fucntion to open the home page after verifying credentials
    def handle_login(self):
        username = self.username_input.text()
        password = self.password_input.text()

        if verify_credentials(username, password):
            self.hide()  # Hiding the login window
            run_home_page()  # Opening the main_page window
        else:
            QtWidgets.QMessageBox.warning(self, "Error", "Incorrect username or password.") # Displaying a message box if the credentials are wrong



# Function to create the database to store users' data (users.db)
def create_user_database():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    # Creating the admin's table (admin)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS admin (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        );
    """)

    # Creating the users' table (users)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        );
    """)

    conn.commit()

    # Checking if system admin exists, if not, creating default system admin
    cursor.execute("SELECT * FROM admin")
    if cursor.fetchone() is None:
        default_admin_password = "admin123"
        password_hash = bcrypt.hashpw(default_admin_password.encode(), bcrypt.gensalt()) # Hashing the admin password using bcrypt in Python

        cursor.execute("INSERT INTO admin (username, password_hash) VALUES (?, ?)", ("admin", password_hash)) # Inserting the admin username and hashed password to the users.db
        conn.commit()

    # Commit and close connection
    cursor.close()
    conn.close()



# Function to verify the login credentials
def verify_credentials(username, password):
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("SELECT password_hash FROM admin WHERE username = ?", (username,))
    record = cursor.fetchone()

    if record:
        password_hash = record[0]
        return bcrypt.checkpw(password.encode(), password_hash)

    cursor.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    record = cursor.fetchone()

    if record:
        password_hash = record[0]
        return bcrypt.checkpw(password.encode(), password_hash)

    cursor.close()
    conn.close()
    return False



# Function to open the home_page window
def run_home_page():
    conn = create_audit_database()
    app = QtWidgets.QApplication.instance()
    if not app:  # If no instance exists, create a new QApplication instance
        app = QtWidgets.QApplication(sys.argv)
    home_page_window = homePage(conn)
    home_page_window.show()



# Main entry of the application (creating the users.db if it doesn't exist and executing the login page, then after verifying the credentials, opening the home page)
def main():
    create_user_database()

    app = QtWidgets.QApplication(sys.argv)

    while True:
        login_form = LoginPage()
        if login_form.exec_() == QtWidgets.QDialog.Accepted:
            run_home_page()
        else:
            break

    sys.exit(app.exec_())


# Executing the main function
if __name__ == "__main__":
    main()