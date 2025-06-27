import sys
import subprocess
import os
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QTextEdit, QMessageBox, QTabWidget, QGroupBox,
    QLineEdit, QComboBox, QSizePolicy, QListWidget, QListWidgetItem
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon

class HelUfwApp(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("HelUfw - Advanced Firewall Manager")
        self.setGeometry(100, 100, 800, 600)

        current_dir = os.path.dirname(os.path.abspath(__file__))
        icon_path = os.path.join(current_dir, "helufw_icon.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        else:
            print(f"Warning: Icon file not found at {icon_path}")

        self.main_layout = QVBoxLayout()
        self.tab_widget = QTabWidget()
        self.main_layout.addWidget(self.tab_widget)

        # --- Tab 1: Status ---
        self.status_tab = QWidget()
        self.status_layout = QVBoxLayout()
        self.status_tab.setLayout(self.status_layout)
        self.tab_widget.addTab(self.status_tab, "Status")

        self.add_status_section()

        # --- Tab 2: Rules ---
        self.rules_tab = QWidget()
        self.rules_layout = QVBoxLayout()
        self.rules_tab.setLayout(self.rules_layout)
        self.tab_widget.addTab(self.rules_tab, "Rules")

        self.add_rule_management_section()

        # --- Tab 3: Settings ---
        self.settings_tab = QWidget()
        self.settings_layout = QVBoxLayout()
        self.settings_tab.setLayout(self.settings_layout)
        self.tab_widget.addTab(self.settings_tab, "Settings")

        self.add_settings_section()

        self.setLayout(self.main_layout)

        # Initial UFW status and rules check.
        # If this fails (e.g., user cancels password), the app should exit.
        if not self.update_all_ufw_info(): # Check return value
            sys.exit(1) # Exit if initial update fails

        self.apply_stylesheet()

    def apply_stylesheet(self):
        """Applies CSS-like styles to the UI."""
        self.setStyleSheet("""
            QWidget {
                font-family: Arial, sans-serif;
                font-size: 14px;
            }
            QLabel#title_label {
                font-size: 24px;
                font-weight: bold;
                color: #2c3e50;
                margin-bottom: 15px;
            }
            QGroupBox {
                border: 1px solid #bdc3c7;
                border-radius: 5px;
                margin-top: 10px;
                padding-top: 15px;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 10px;
                background-color: #ecf0f1;
                color: #34495e;
                font-weight: bold;
            }
            QPushButton {
                background-color: #3498db;
                color: white;
                border: none;
                padding: 10px 15px;
                border-radius: 5px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #2980b9;
            }
            QPushButton:pressed {
                background-color: #21618C;
            }
            QTextEdit, QLineEdit, QComboBox, QListWidget {
                border: 1px solid #ccc;
                border-radius: 4px;
                padding: 5px;
            }
            QTextEdit {
                background-color: #f8f9fa;
            }
            QListWidget::item {
                padding: 5px;
            }
            QListWidget::item:selected {
                background-color: #aed6f1;
            }
        """)

    def add_status_section(self):
        """Adds the UFW status section to the Status tab."""
        status_group = QGroupBox("UFW Status and Control")
        status_group.setObjectName("status_group_box")
        status_layout = QVBoxLayout()
        status_group.setLayout(status_layout)

        self.title_label = QLabel("HelUfw Firewall Manager")
        self.title_label.setObjectName("title_label")
        self.title_label.setAlignment(Qt.AlignCenter)
        status_layout.addWidget(self.title_label)

        self_status_layout = QHBoxLayout()
        self_status_layout.addStretch()
        self_status_layout.addWidget(QLabel("Current Status:"))
        self.ufw_status_label = QLabel("Unknown")
        self.ufw_status_label.setStyleSheet("font-size: 16px; font-weight: bold;")
        self_status_layout.addWidget(self.ufw_status_label)
        self_status_layout.addStretch()
        status_layout.addLayout(self_status_layout)

        button_layout = QHBoxLayout()
        self.status_button = QPushButton("Refresh Status")
        # Keep this connected to update_all_ufw_info as it needs root
        self.status_button.clicked.connect(self.update_all_ufw_info) 
        button_layout.addWidget(self.status_button)

        self.enable_button = QPushButton("Enable UFW")
        self.enable_button.clicked.connect(self.enable_ufw)
        button_layout.addWidget(self.enable_button)

        self.disable_button = QPushButton("Disable UFW")
        self.disable_button.clicked.connect(self.disable_ufw)
        button_layout.addWidget(self.disable_button)
        status_layout.addLayout(button_layout)

        status_layout.addWidget(QLabel("UFW Output/Details:"))
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        status_layout.addWidget(self.output_text)

        self.status_tab.layout().addWidget(status_group)

    def add_rule_management_section(self):
        """Adds the rule management section to the Rules tab."""
        # Add Rule Group
        add_rule_group = QGroupBox("Add New Rule")
        add_rule_layout = QVBoxLayout()
        add_rule_group.setLayout(add_rule_layout)

        # Rule Type (Allow/Deny)
        rule_type_layout = QHBoxLayout()
        rule_type_layout.addWidget(QLabel("Action:"))
        self.rule_action_combo = QComboBox()
        self.rule_action_combo.addItems(["Allow", "Deny"])
        rule_type_layout.addWidget(self.rule_action_combo)
        rule_type_layout.addStretch()
        add_rule_layout.addLayout(rule_type_layout)

        # Port and Protocol
        port_proto_layout = QHBoxLayout()
        port_proto_layout.addWidget(QLabel("Port:"))
        self.port_input = QLineEdit()
        self.port_input.setPlaceholderText("e.g., 80, 22, 1024:65535")
        port_proto_layout.addWidget(self.port_input)
        port_proto_layout.addWidget(QLabel("Protocol:"))
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["", "tcp", "udp"]) # Empty for "any"
        port_proto_layout.addWidget(self.protocol_combo)
        add_rule_layout.addLayout(port_proto_layout)

        # Direction and Comment
        dir_comment_layout = QHBoxLayout()
        dir_comment_layout.addWidget(QLabel("Direction:"))
        self.direction_combo = QComboBox()
        self.direction_combo.addItems(["", "in", "out"]) # Empty for "any"
        dir_comment_layout.addWidget(self.direction_combo)
        dir_comment_layout.addWidget(QLabel("Comment (Optional):"))
        self.comment_input = QLineEdit()
        self.comment_input.setPlaceholderText("e.g., Allow SSH")
        dir_comment_layout.addWidget(self.comment_input)
        add_rule_layout.addLayout(dir_comment_layout)

        self.add_rule_button = QPushButton("Add Rule")
        self.add_rule_button.clicked.connect(self.add_ufw_rule)
        add_rule_layout.addWidget(self.add_rule_button)

        self.rules_tab.layout().addWidget(add_rule_group)

        # Display Rules Group
        display_rules_group = QGroupBox("Existing Rules")
        display_rules_layout = QVBoxLayout()
        display_rules_group.setLayout(display_rules_layout)

        self.rules_list_widget = QListWidget()
        self.rules_list_widget.clicked.connect(self.on_rule_selected)
        display_rules_layout.addWidget(self.rules_list_widget)

        rules_buttons_layout = QHBoxLayout()
        self.refresh_rules_button = QPushButton("Refresh Rules")
        # This also needs root for 'ufw status numbered', so connect to update_all_ufw_info
        self.refresh_rules_button.clicked.connect(self.update_all_ufw_info) 
        rules_buttons_layout.addWidget(self.refresh_rules_button)

        self.delete_rule_button = QPushButton("Delete Selected Rule")
        self.delete_rule_button.setEnabled(False)
        self.delete_rule_button.clicked.connect(self.delete_ufw_rule)
        rules_buttons_layout.addWidget(self.delete_rule_button)

        display_rules_layout.addLayout(rules_buttons_layout)
        self.rules_tab.layout().addWidget(display_rules_group)

    def add_settings_section(self):
        """Adds the settings section to the Settings tab."""
        reset_group = QGroupBox("Reset UFW")
        reset_layout = QVBoxLayout()
        reset_group.setLayout(reset_layout)

        reset_layout.addWidget(QLabel("This will reset all UFW rules to default. Use with caution!"))
        self.reset_button = QPushButton("Reset UFW to Defaults")
        self.reset_button.clicked.connect(self.reset_ufw)
        reset_layout.addWidget(self.reset_button)
        self.settings_tab.layout().addWidget(reset_group)

        logging_group = QGroupBox("UFW Logging")
        logging_layout = QVBoxLayout()
        logging_group.setLayout(logging_layout)

        logging_layout.addWidget(QLabel("Control UFW logging level."))
        logging_buttons_layout = QHBoxLayout()
        self.logging_on_button = QPushButton("Enable Logging")
        self.logging_on_button.clicked.connect(lambda: self.set_ufw_logging("on"))
        logging_buttons_layout.addWidget(self.logging_on_button)

        self.logging_off_button = QPushButton("Disable Logging")
        self.logging_off_button.clicked.connect(lambda: self.set_ufw_logging("off"))
        logging_buttons_layout.addWidget(self.logging_off_button)

        self.logging_low_button = QPushButton("Logging: Low")
        self.logging_low_button.clicked.connect(lambda: self.set_ufw_logging("low"))
        logging_buttons_layout.addWidget(self.logging_low_button)

        logging_layout.addLayout(logging_buttons_layout)
        self.settings_tab.layout().addWidget(logging_group)

    def _run_admin_command(self, command, check_output=True, success_msg="Command executed successfully."):
        """
        Executes a command requiring administrative privileges using pkexec.
        Returns (True, output) on success, (False, error_message) on failure.
        """
        full_command = f"pkexec bash -c '{command}'"

        try:
            if check_output:
                result = subprocess.run(full_command, capture_output=True, text=True, check=True, shell=True)
                return True, result.stdout.strip()
            else:
                subprocess.run(full_command, check=True, shell=True)
                return True, success_msg
        except subprocess.CalledProcessError as e:
            error_message = (
                f"Failed to execute command. This usually means: \n"
                f"1. You cancelled the password prompt.\n"
                f"2. You entered an incorrect password.\n"
                f"3. 'pkexec' is not installed or configured correctly.\n\n"
                f"Error details: {e.stderr}"
            )
            QMessageBox.critical(self.parent(), "Admin Command Error", error_message)
            return False, error_message # Return False on failure
        except FileNotFoundError:
            error_message = "The 'pkexec' command was not found. Please ensure PolicyKit is installed and configured."
            QMessageBox.critical(self.parent(), "Error", error_message)
            return False, error_message # Return False on failure
        except Exception as e:
            error_message = f"An unexpected error occurred: {e}"
            QMessageBox.critical(self.parent(), "Unexpected Error", error_message)
            return False, error_message # Return False on failure

    def update_output_text(self, text):
        """Updates the text displayed in the output area."""
        self.output_text.setText(text)

    def update_all_ufw_info(self):
        """
        Fetches full UFW status and rules and updates all relevant UI elements.
        This call will always trigger an admin prompt as 'ufw status verbose numbered' requires root.
        Returns True if successful, False otherwise (e.g., if user cancels password prompt).
        """
        success, full_status_output = self._run_admin_command("ufw status verbose numbered")
        
        if not success:
            # If command failed (e.g., user cancelled), don't update UI, just return False
            return False

        # Update status label
        if "Status: active" in full_status_output:
            self.ufw_status_label.setText("Active ✅")
            self.ufw_status_label.setStyleSheet("font-size: 16px; font-weight: bold; color: green;")
        elif "Status: inactive" in full_status_output:
            self.ufw_status_label.setText("Inactive ❌")
            self.ufw_status_label.setStyleSheet("font-size: 16px; font-weight: bold; color: red;")
        else:
            self.ufw_status_label.setText("Unknown ❓")
            self.ufw_status_label.setStyleSheet("font-size: 16px; font-weight: bold; color: orange;")
        
        # Update detailed output text area
        self.update_output_text(full_status_output)

        # Update rules list
        self._parse_and_display_rules(full_status_output)
        return True # Return True on successful update


    def enable_ufw(self):
        """Enables UFW after user confirmation."""
        reply = QMessageBox.question(self, "Confirmation",
                                     "Are you sure you want to enable UFW? This might affect current connections.\n\n"
                                     "You will need to click 'Refresh Status' after this operation to update the display.",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            success, result_message = self._run_admin_command("ufw enable", success_msg="UFW enabled successfully.")
            self.update_output_text(result_message)
            if success: # Only update status if the command actually ran
                self.ufw_status_label.setText("Status pending refresh...")
                self.ufw_status_label.setStyleSheet("font-size: 16px; font-weight: bold; color: blue;")


    def disable_ufw(self):
        """Disables UFW after user confirmation."""
        reply = QMessageBox.question(self, "Confirmation",
                                     "Are you sure you want to disable UFW? This might expose your system to risks.\n\n"
                                     "You will need to click 'Refresh Status' after this operation to update the display.",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            success, result_message = self._run_admin_command("ufw disable", success_msg="UFW disabled successfully.")
            self.update_output_text(result_message)
            if success: # Only update status if the command actually ran
                self.ufw_status_label.setText("Status pending refresh...")
                self.ufw_status_label.setStyleSheet("font-size: 16px; font-weight: bold; color: blue;")

    def load_ufw_rules(self):
        """Loads and displays UFW rules in the list widget. (Still separate for rules tab refresh)"""
        success, rules_output = self._run_admin_command("ufw status numbered")
        if success: # Only parse and display if command succeeded
            self._parse_and_display_rules(rules_output)
        self.delete_rule_button.setEnabled(False)

    def _parse_and_display_rules(self, rules_output):
        """Helper to parse ufw status output and populate the rules list."""
        self.rules_list_widget.clear()
        lines = rules_output.splitlines()

        if not lines or "Status: inactive" in lines[0]:
            self.rules_list_widget.addItem("UFW is inactive or no rules defined.")
            return

        start_index = 0
        header_found = False
        for i, line in enumerate(lines):
            if ("To" in line and "Action" in line and "From" in line) or \
               ("-----" in line and i > 0 and lines[i-1].strip().startswith("To")):
                start_index = i + 1
                header_found = True
                break
        
        if not header_found and len(lines) > 2:
            for i, line in enumerate(lines):
                if line.strip().startswith(('1 ', '2 ', '3 ', '4 ', '5 ', '6 ', '7 ', '8 ', '9 ')):
                    start_index = i
                    break
        
        found_rules = False
        for i in range(start_index, len(lines)):
            line = lines[i].strip()
            if line and line[0].isdigit() and '  ' in line:
                self.rules_list_widget.addItem(line)
                found_rules = True
            
        if not found_rules:
            self.rules_list_widget.addItem("No rules defined.")


    def on_rule_selected(self):
        """Enables the delete button when a rule is selected."""
        self.delete_rule_button.setEnabled(True)

    def add_ufw_rule(self):
        """Adds a new UFW rule based on user input."""
        action = self.rule_action_combo.currentText().lower()
        port = self.port_input.text().strip()
        protocol = self.protocol_combo.currentText().lower()
        direction = self.direction_combo.currentText().lower()
        comment = self.comment_input.text().strip()

        if not port:
            QMessageBox.warning(self, "Missing Information", "Please enter a port or port range.")
            return

        ufw_cmd = f"ufw {action} {port}"
        if protocol:
            ufw_cmd += f"/{protocol}"
        if direction:
            ufw_cmd += f" {direction}"

        confirm_msg = f"Are you sure you want to add this rule?\n\nCommand: {ufw_cmd}\n\n" \
                      "You will need to click 'Refresh Status' or 'Refresh Rules' after this operation to update the display."

        reply = QMessageBox.question(self, "Confirm Add Rule", confirm_msg,
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            success, result_message = self._run_admin_command(ufw_cmd, success_msg=f"Rule '{ufw_cmd}' added successfully.")
            self.update_output_text(result_message)
            if success: # Only update status if the command actually ran
                self.ufw_status_label.setText("Status/Rules pending refresh...")
                self.ufw_status_label.setStyleSheet("font-size: 16px; font-weight: bold; color: blue;")


    def delete_ufw_rule(self):
        """Deletes the selected rule from the list."""
        selected_item = self.rules_list_widget.currentItem()
        if not selected_item:
            QMessageBox.warning(self, "No Rule Selected", "Please select a rule to delete.")
            return

        rule_text = selected_item.text()
        try:
            rule_number = int(rule_text.split(' ')[0].strip())
        except ValueError:
            QMessageBox.critical(self, "Error Parsing Rule", "Could not extract rule number. Please select a valid numbered rule.")
            return

        confirm_msg = f"Are you sure you want to delete rule number {rule_number}?\n\nRule: {rule_text}\n\n" \
                      "You will need to click 'Refresh Status' or 'Refresh Rules' after this operation to update the display."
        reply = QMessageBox.question(self, "Confirm Delete Rule", confirm_msg,
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            success, result_message = self._run_admin_command(f"ufw delete {rule_number}", success_msg=f"Rule {rule_number} deleted successfully.")
            self.update_output_text(result_message)
            if success: # Only update status if the command actually ran
                self.ufw_status_label.setText("Status/Rules pending refresh...")
                self.ufw_status_label.setStyleSheet("font-size: 16px; font-weight: bold; color: blue;")
                self.delete_rule_button.setEnabled(False)

    def reset_ufw(self):
        """Resets UFW to default settings."""
        reply = QMessageBox.question(self, "Confirm Reset",
                                     "This will DELETE ALL UFW rules and reset to defaults. This action cannot be undone. Are you absolutely sure?\n\n"
                                     "You will need to click 'Refresh Status' after this operation to update the display.",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            success, result_message = self._run_admin_command("ufw --force reset", success_msg="UFW has been reset to defaults.")
            self.update_output_text(result_message)
            if success: # Only update status if the command actually ran
                self.ufw_status_label.setText("Status/Rules pending refresh...")
                self.ufw_status_label.setStyleSheet("font-size: 16px; font-weight: bold; color: blue;")

    def set_ufw_logging(self, level):
        """Enables/disables UFW logging or sets its level."""
        confirm_msg = f"Are you sure you want to set UFW logging to '{level}'?"
        reply = QMessageBox.question(self, "Confirm Logging Change", confirm_msg,
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            success, result_message = self._run_admin_command(f"ufw logging {level}", success_msg=f"UFW logging set to '{level}'.")
            self.update_output_text(result_message)
            # No need to call update_all_ufw_info here, as logging changes don't affect rules/status directly
            # and 'ufw status verbose' might not show immediate logging level change clearly.

if __name__ == "__main__":
    app = QApplication(sys.argv)
    ex = HelUfwApp()
    ex.show()
    sys.exit(app.exec_())
