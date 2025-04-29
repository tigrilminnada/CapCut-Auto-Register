import customtkinter as ctk
from tkinter import messagebox
import threading
import time
import re
import imaplib
import email
from email.header import decode_header
import requests
import json
from datetime import datetime
import os
import configparser

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

class CapCutRegistrarApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Masanto CapCut Bulk Register Pro")
        self.root.geometry("1100x800")
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        self.config = configparser.ConfigParser()
        self.load_config()
        self.success_count = 0
        self.failure_count = 0
        self.total_processed = 0
        self.main_frame = ctk.CTkFrame(self.root, corner_radius=10)
        self.main_frame.grid(row=0, column=0, padx=20, pady=20, sticky="nsew")
        self.main_frame.grid_columnconfigure(0, weight=1)
        self.main_frame.grid_rowconfigure(1, weight=1)
        self.header_frame = ctk.CTkFrame(self.main_frame, fg_color="transparent")
        self.header_frame.grid(row=0, column=0, padx=20, pady=(10, 5), sticky="ew")
        
        self.header_label = ctk.CTkLabel(
            self.header_frame, 
            text="MASANTO CAPCUT BULK REGISTER PRO", 
            font=("Helvetica", 22, "bold"),
            text_color="#4CC9F0"
        )
        self.header_label.pack(side="left")
        
        # Stats frame Cok
        self.stats_frame = ctk.CTkFrame(self.header_frame, fg_color="transparent")
        self.stats_frame.pack(side="right", padx=10)
        
        self.stats_label = ctk.CTkLabel(
            self.stats_frame,
            text="Stats: Success(0) | Failed(0) | Total(0)",
            font=("Helvetica", 12)
        )
        self.stats_label.pack(side="right")
        
        # Content Lek
        self.content_frame = ctk.CTkFrame(self.main_frame, corner_radius=10)
        self.content_frame.grid(row=1, column=0, padx=20, pady=10, sticky="nsew")
        self.content_frame.grid_columnconfigure(0, weight=1)
        self.content_frame.grid_columnconfigure(1, weight=1)
        self.content_frame.grid_rowconfigure(0, weight=1)
        
        # Left panel (Input)
        self.left_panel = ctk.CTkFrame(self.content_frame, corner_radius=10)
        self.left_panel.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
        self.left_panel.grid_columnconfigure(0, weight=1)
        
        # IMAP Card
        self.imap_card = ctk.CTkFrame(self.left_panel, corner_radius=10)
        self.imap_card.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        
        ctk.CTkLabel(
            self.imap_card, 
            text="IMAP CONFIGURATION", 
            font=("Helvetica", 14, "bold"),
            anchor="w"
        ).grid(row=0, column=0, padx=10, pady=(10, 5), sticky="ew", columnspan=2)
        
        # IMAP Server Input
        self.imap_server_var = ctk.StringVar(value=self.config.get('IMAP', 'host', fallback="imap.example.com"))
        ctk.CTkLabel(self.imap_card, text="IMAP Server:").grid(row=1, column=0, padx=10, pady=5, sticky="w")
        self.imap_server_entry = ctk.CTkEntry(self.imap_card, textvariable=self.imap_server_var)
        self.imap_server_entry.grid(row=1, column=1, padx=10, pady=5, sticky="ew")
        
        # IMAP Port Input
        self.imap_port_var = ctk.StringVar(value=self.config.get('IMAP', 'port', fallback="993"))
        ctk.CTkLabel(self.imap_card, text="IMAP Port:").grid(row=2, column=0, padx=10, pady=5, sticky="w")
        self.imap_port_entry = ctk.CTkEntry(self.imap_card, textvariable=self.imap_port_var, width=80)
        self.imap_port_entry.grid(row=2, column=1, padx=10, pady=5, sticky="w")
        
        # Email Accounts Card
        self.accounts_card = ctk.CTkFrame(self.left_panel, corner_radius=10)
        self.accounts_card.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        self.accounts_card.grid_columnconfigure(0, weight=1)
        self.accounts_card.grid_rowconfigure(1, weight=1)
        
        ctk.CTkLabel(
            self.accounts_card, 
            text="EMAIL ACCOUNTS (one per line)", 
            font=("Helvetica", 14, "bold"),
            anchor="w"
        ).grid(row=0, column=0, padx=10, pady=(10, 5), sticky="ew")
        
        # Email Accounts Textbox
        self.accounts_text = ctk.CTkTextbox(self.accounts_card, wrap="none")
        self.accounts_text.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        self.accounts_text.insert("1.0", "email1@example.com\nemail2@example.com")
        
        # Control Buttons
        self.control_frame = ctk.CTkFrame(self.left_panel, corner_radius=10)
        self.control_frame.grid(row=2, column=0, padx=5, pady=5, sticky="ew")
        
        self.start_button = ctk.CTkButton(
            self.control_frame, 
            text="START REGISTRATION", 
            command=self.start_registration,
            fg_color="#4CAF50",
            hover_color="#45a049",
            font=("Helvetica", 12, "bold"),
            height=35
        )
        self.start_button.pack(side="left", padx=10, pady=10, expand=True)
        
        self.stop_button = ctk.CTkButton(
            self.control_frame, 
            text="STOP", 
            command=self.stop_registration,
            fg_color="#f44336",
            hover_color="#d32f2f",
            font=("Helvetica", 12, "bold"),
            height=35,
            state="disabled"
        )
        self.stop_button.pack(side="left", padx=10, pady=10, expand=True)
        
        # Right panel (Results)
        self.right_panel = ctk.CTkFrame(self.content_frame, corner_radius=10)
        self.right_panel.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
        self.right_panel.grid_columnconfigure(0, weight=1)
        self.right_panel.grid_rowconfigure(1, weight=1)
        
        # Results Card
        self.results_card = ctk.CTkFrame(self.right_panel, corner_radius=10)
        self.results_card.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
        self.results_card.grid_columnconfigure(0, weight=1)
        self.results_card.grid_rowconfigure(1, weight=1)
        
        ctk.CTkLabel(
            self.results_card, 
            text="REGISTRATION RESULTS", 
            font=("Helvetica", 14, "bold"),
            anchor="w"
        ).grid(row=0, column=0, padx=10, pady=(10, 5), sticky="ew")
        
        # Results Textbox
        self.results_text = ctk.CTkTextbox(self.results_card, wrap="word")
        self.results_text.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        
        # Success Card
        self.success_card = ctk.CTkFrame(self.right_panel, corner_radius=10)
        self.success_card.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
        self.success_card.grid_columnconfigure(0, weight=1)
        self.success_card.grid_rowconfigure(1, weight=1)
        
        ctk.CTkLabel(
            self.success_card, 
            text="SUCCESSFUL REGISTRATIONS", 
            font=("Helvetica", 14, "bold"),
            anchor="w"
        ).grid(row=0, column=0, padx=10, pady=(10, 5), sticky="ew")
        
        # Success Textbox
        self.success_text = ctk.CTkTextbox(self.success_card, wrap="word")
        self.success_text.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        
        # Configure weights for resizing
        self.left_panel.grid_rowconfigure(1, weight=1)
        self.right_panel.grid_rowconfigure(0, weight=3)
        self.right_panel.grid_rowconfigure(1, weight=2)
        
        # Registration control variables
        self.is_running = False
        self.current_thread = None
    
    def load_config(self):
        if not os.path.exists('config.ini'):
            self.create_default_config()
        self.config.read('config.ini')
    
    def create_default_config(self):
        self.config['IMAP'] = {
            'host': 'imap.example.com',
            'port': '993',
            'password': '',  # IMAP password will be stored here
            'ssl': 'True'
        }
        self.config['CAPCUT'] = {
            'password': ''  # CapCut password will be stored here
        }
        with open('config.ini', 'w') as configfile:
            self.config.write(configfile)
    
    def update_stats_display(self):
        self.stats_label.configure(
            text=f"Stats: Success({self.success_count}) | Failed({self.failure_count}) | Total({self.total_processed})"
        )
    
    def log_message(self, message, result_type="info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        tag = ""
        color = ""
        
        if result_type == "success":
            tag = "SUCCESS"
            color = "#4CAF50"
        elif result_type == "error":
            tag = "ERROR"
            color = "#f44336"
        else:
            tag = "INFO"
            color = "#2196F3"
        
        self.results_text.insert("end", f"[{timestamp}] [{tag}] {message}\n")
        self.results_text.tag_config(tag, foreground=color)
        self.results_text.see("end")
        self.root.update()
    
    def log_success(self, email, user_id, name):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = f"{timestamp} | {email} | ID: {user_id} | Name: {name}\n"
        
        self.success_text.insert("end", entry)
        self.success_text.see("end")
        
        # Also log to file
        with open("sukses.txt", "a", encoding="utf-8") as f:
            f.write(entry)
        
        self.success_count += 1
        self.update_stats_display()
        
        # Show notification
        self.show_notification(f"Registration Success!\n{email}")
    
    def log_failure(self, email, error_msg):
        self.failure_count += 1
        self.update_stats_display()
        
        # Show notification
        self.show_notification(f"Registration Failed\n{email}\nError: {error_msg}", is_error=True)
    
    def show_notification(self, message, is_error=False):
        # Create a temporary toplevel window for notification
        notif = ctk.CTkToplevel(self.root)
        notif.title("Notification" if not is_error else "Error")
        notif.geometry("300x150")
        notif.attributes("-topmost", True)
        notif.resizable(False, False)
        
        # Center the notification
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - 150
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - 75
        notif.geometry(f"+{x}+{y}")
        
        # Notification content
        icon = "✓" if not is_error else "✗"
        color = "#4CAF50" if not is_error else "#f44336"
        
        ctk.CTkLabel(
            notif,
            text=icon,
            font=("Helvetica", 24),
            text_color=color
        ).pack(pady=5)
        
        ctk.CTkLabel(
            notif,
            text=message,
            font=("Helvetica", 12),
            wraplength=280
        ).pack(pady=5, padx=10)
        
        # Auto-close after 3 seconds
        notif.after(3000, notif.destroy)
    
    def encrypt_to_target_hex(self, input_str):
        hex_result = ""
        for char in input_str:
            encrypted_char_code = ord(char) ^ 0x05
            hex_result += f"{encrypted_char_code:02x}"
        return hex_result
    
    def fetch_email_otp(self, recipient_email, imap_config):
        try:
            mail = imaplib.IMAP4_SSL(imap_config['host'], int(imap_config['port']))
            mail.login(recipient_email, imap_config['password'])  # Use email as username
            mail.select('inbox')
            
            search_criteria = f'(SUBJECT "Welcome to CapCut" TO "{recipient_email}")'
            status, messages = mail.search(None, search_criteria)
            
            if status != 'OK' or not messages[0]:
                raise Exception("No CapCut verification emails found")
            
            # Get the latest email
            latest_email_id = messages[0].split()[-1]
            status, msg_data = mail.fetch(latest_email_id, '(RFC822)')
            
            if status != 'OK':
                raise Exception("Failed to fetch email")
            
            msg = email.message_from_bytes(msg_data[0][1])
            subject = decode_header(msg['Subject'])[0][0]
            if isinstance(subject, bytes):
                subject = subject.decode()
            
            self.log_message(f"Found email with subject: {subject}")
            
            # Extract OTP from subject
            otp_match = re.search(r'Welcome to CapCut and your verification code is (\d+)', subject, re.IGNORECASE)
            if otp_match and otp_match.group(1):
                return otp_match.group(1)
            else:
                raise Exception("OTP not found in subject or unexpected subject format")
                
        except Exception as e:
            raise Exception(f"IMAP error: {str(e)}")
        finally:
            try:
                mail.logout()
            except:
                pass
    
    def get_otp_with_retry(self, email, imap_config, max_retries=10, delay=5):
        self.log_message(f"Waiting for verification email for {email}...")
        
        for attempt in range(1, max_retries + 1):
            try:
                self.log_message(f"Attempt {attempt}/{max_retries} to retrieve OTP...")
                otp = self.fetch_email_otp(email, imap_config)
                self.log_message(f"✓ Successfully retrieved OTP: {otp}", "success")
                return otp
            except Exception as e:
                self.log_message(f"Attempt {attempt} failed: {str(e)}", "error")
                if attempt < max_retries:
                    self.log_message(f"Waiting {delay} seconds before next attempt...")
                    time.sleep(delay)
                else:
                    raise Exception(f"Failed to retrieve OTP after {max_retries} attempts")
    
    def request_otp(self, email):
        encrypted_email = self.encrypt_to_target_hex(email)
        encrypted_password = self.encrypt_to_target_hex(self.config['CAPCUT']['password'])
        
        data = f"mix_mode=1&email={encrypted_email}&password={encrypted_password}&type=34&fixed_mix_mode=1"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Content-Type': 'application/x-www-form-urlencoded',
            'Referer': 'https://www.capcut.com/signup',
            'Accept-Encoding': 'gzip, deflate, br',
            'Accept-Language': 'en-US,en;q=0.9',
        }
        
        try:
            response = requests.post(
                'https://www.capcut.com/passport/web/email/send_code/?aid=348188&account_sdk_source=web&language=en&verifyFp=verify_m8g4hof0_ouOjuj3A_ejmE_4tHy_A8QW_aISsO1HusMC5&check_region=1',
                headers=headers,
                data=data,
                timeout=30
            )
            return response.json()
        except Exception as e:
            raise Exception(f"Request OTP failed: {str(e)}")
    
    def verify_registration(self, email, otp_code):
        encrypted_email = self.encrypt_to_target_hex(email)
        encrypted_password = self.encrypt_to_target_hex(self.config['CAPCUT']['password'])
        encrypted_otp = self.encrypt_to_target_hex(otp_code)
        
        data = f"mix_mode=1&email={encrypted_email}&code={encrypted_otp}&password={encrypted_password}&type=34&birthday=343c3c3c283536283536&force_user_region=ES&biz_param=%7B%22invite_code%22%3A%22%22%7D&check_region=1&fixed_mix_mode=1"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/134.0.0.0 Safari/537.36',
            'Sec-Ch-Ua': '"Chromium";v="134", "Not:A-Brand";v="24", "Google Chrome";v="134"',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        
        try:
            response = requests.post(
                'https://www.capcut.com/passport/web/email/register_verify_login/?aid=348188&account_sdk_source=web&language=en&verifyFp=verify_m8g4hof0_ouOjuj3A_ejmE_4tHy_A8QW_aISsO1HusMC5&check_region=1',
                headers=headers,
                data=data,
                timeout=30
            )
            return response.json()
        except Exception as e:
            raise Exception(f"Verify registration failed: {str(e)}")
    
    def process_accounts(self):
        # Get IMAP configuration from UI and config file
        imap_config = {
            'host': self.imap_server_var.get(),
            'port': self.imap_port_var.get(),
            'password': self.config['IMAP']['password'],  # Password from config.ini
            'ssl': True
        }
        
        # Update config file with current settings
        self.config['IMAP']['host'] = self.imap_server_var.get()
        self.config['IMAP']['port'] = self.imap_port_var.get()
        with open('config.ini', 'w') as configfile:
            self.config.write(configfile)
        
        # Get accounts from textbox (only emails)
        accounts_text = self.accounts_text.get("1.0", "end-1c")
        accounts = [email.strip() for email in accounts_text.split('\n') if email.strip()]
        
        if not accounts:
            messagebox.showwarning("Warning", "No valid email accounts found in the input!")
            return
        
        self.total_processed = len(accounts)
        self.update_stats_display()
        self.log_message(f"Starting registration for {len(accounts)} accounts...")
        
        for idx, email in enumerate(accounts, 1):
            if not self.is_running:
                break
                
            self.log_message(f"\nProcessing account {idx}/{len(accounts)}: {email}")
            
            try:
                # Request OTP
                self.log_message("Requesting OTP code...")
                otp_response = self.request_otp(email)
                
                if otp_response.get('message') == "success":
                    self.log_message("✓ OTP code sent! Waiting for verification email...", "success")
                    
                    try:
                        # Get OTP from email
                        otp_code = self.get_otp_with_retry(email, imap_config)
                        
                        # Verify registration
                        self.log_message(f"Verifying registration with OTP: {otp_code}")
                        verify_response = self.verify_registration(email, otp_code)
                        
                        if verify_response.get('message') == "success":
                            user_id = verify_response.get('data', {}).get('user_id', 'N/A')
                            name = verify_response.get('data', {}).get('name', 'N/A')
                            
                            self.log_message("\n==== Registration Result ====")
                            self.log_message(f"Email: {email}")
                            self.log_message(f"User ID: {user_id}")
                            self.log_message(f"Name: {name}")
                            self.log_message("\n✓ Registration completed successfully!", "success")
                            
                            # Log success
                            self.log_success(email, user_id, name)
                            
                        else:
                            error_msg = verify_response.get('message', 'Unknown error')
                            self.log_message(f"\n✗ Registration failed: {error_msg}", "error")
                            self.log_failure(email, error_msg)
                            
                    except Exception as otp_error:
                        self.log_message(f"\n✗ Failed to get OTP: {str(otp_error)}", "error")
                        self.log_failure(email, f"OTP Error: {str(otp_error)}")
                        
                else:
                    error_msg = otp_response.get('description', otp_response.get('message', 'Unknown error'))
                    self.log_message(f"\n✗ Failed to send OTP: {error_msg}", "error")
                    self.log_failure(email, f"OTP Send Error: {error_msg}")
                    
            except Exception as e:
                self.log_message(f"\n✗ Error during registration: {str(e)}", "error")
                self.log_failure(email, f"General Error: {str(e)}")
            
            self.log_message("\n" + "-"*50)
            
            if idx < len(accounts) and self.is_running:
                time.sleep(5)  # Delay between accounts
        
        self.log_message("\nRegistration process completed!")
        self.stop_registration()
    
    def start_registration(self):
        if not self.accounts_text.get("1.0", "end-1c").strip():
            messagebox.showerror("Error", "Please enter valid email accounts!")
            return
            
        if not self.config['IMAP'].get('password'):
            messagebox.showerror("Error", "Please configure IMAP password in config.ini!")
            return
            
        if not self.config['CAPCUT'].get('password'):
            messagebox.showerror("Error", "Please configure CapCut password in config.ini!")
            return
            
        self.is_running = True
        self.start_button.configure(state="disabled")
        self.stop_button.configure(state="normal")
        
        # Reset stats
        self.success_count = 0
        self.failure_count = 0
        self.total_processed = 0
        self.update_stats_display()
        
        # Clear results
        self.results_text.delete("1.0", "end")
        self.success_text.delete("1.0", "end")
        
        # Start processing in a separate thread
        self.current_thread = threading.Thread(target=self.process_accounts, daemon=True)
        self.current_thread.start()
    
    def stop_registration(self):
        self.is_running = False
        self.start_button.configure(state="normal")
        self.stop_button.configure(state="disabled")
        
        if self.current_thread and self.current_thread.is_alive():
            self.log_message("\nStopping registration process...")

if __name__ == "__main__":
    root = ctk.CTk()
    app = CapCutRegistrarApp(root)
    root.mainloop()
