"""
GUI for Secure File Transfer System
Demonstrates Forward Secrecy and Encrypted File Transfer
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import os
import threading
from datetime import datetime
from transfer_protocol import SecureFileTransfer, TransferSession


class SecureFileTransferGUI:
    """Main GUI Application for Secure File Transfer"""

    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Transfer with Forward Secrecy")
        self.root.geometry("1200x800")
        self.root.resizable(True, True)

        # Transfer protocol instance
        self.transfer_protocol = SecureFileTransfer()
        self.sender_session = None
        self.receiver_session = None

        # File paths
        self.selected_file = None
        self.output_directory = os.path.expanduser("~/Desktop")

        # Setup GUI
        self.setup_styles()
        self.create_widgets()

    def setup_styles(self):
        """Setup custom styles for the GUI"""
        style = ttk.Style()
        style.theme_use('clam')

        # Custom colors
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'), foreground='#2c3e50')
        style.configure('Header.TLabel', font=('Arial', 12, 'bold'), foreground='#34495e')
        style.configure('Status.TLabel', font=('Arial', 10), foreground='#27ae60')
        style.configure('Info.TLabel', font=('Arial', 9), foreground='#7f8c8d')

        style.configure('Primary.TButton', font=('Arial', 10, 'bold'))
        style.configure('Success.TButton', font=('Arial', 10, 'bold'), foreground='#27ae60')
        style.configure('Danger.TButton', font=('Arial', 10, 'bold'), foreground='#c0392b')

    def create_widgets(self):
        """Create all GUI widgets"""
        # Main title
        title_frame = ttk.Frame(self.root, padding="10")
        title_frame.pack(fill=tk.X)

        ttk.Label(
            title_frame,
            text="Secure File Transfer with Forward Secrecy",
            style='Title.TLabel'
        ).pack()

        ttk.Label(
            title_frame,
            text="Demonstrating Diffie-Hellman Key Exchange and Encrypted File Transfer",
            style='Info.TLabel'
        ).pack()

        # Main container with two panels
        main_container = ttk.Frame(self.root, padding="10")
        main_container.pack(fill=tk.BOTH, expand=True)

        # Left panel (Sender)
        self.create_sender_panel(main_container)

        # Separator
        ttk.Separator(main_container, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=5)

        # Right panel (Receiver)
        self.create_receiver_panel(main_container)

        # Bottom log panel
        self.create_log_panel(self.root)

    def create_sender_panel(self, parent):
        """Create sender panel"""
        sender_frame = ttk.Frame(parent, padding="10")
        sender_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Header
        ttk.Label(sender_frame, text="SENDER", style='Header.TLabel').pack(anchor=tk.W)
        ttk.Separator(sender_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)

        # File selection
        file_frame = ttk.LabelFrame(sender_frame, text="1. Select File", padding="10")
        file_frame.pack(fill=tk.X, pady=5)

        self.sender_file_label = ttk.Label(file_frame, text="No file selected", style='Info.TLabel')
        self.sender_file_label.pack(anchor=tk.W)

        ttk.Button(
            file_frame,
            text="Choose File",
            command=self.select_file,
            style='Primary.TButton'
        ).pack(pady=5)

        # Session info
        session_frame = ttk.LabelFrame(sender_frame, text="2. Session Information", padding="10")
        session_frame.pack(fill=tk.X, pady=5)

        self.sender_session_text = scrolledtext.ScrolledText(
            session_frame,
            height=6,
            width=40,
            font=('Courier', 9),
            state=tk.DISABLED
        )
        self.sender_session_text.pack(fill=tk.BOTH)

        # Handshake
        handshake_frame = ttk.LabelFrame(sender_frame, text="3. Handshake & Key Exchange", padding="10")
        handshake_frame.pack(fill=tk.X, pady=5)

        ttk.Button(
            handshake_frame,
            text="Initiate Handshake",
            command=self.initiate_handshake,
            style='Primary.TButton'
        ).pack(pady=5)

        self.sender_handshake_status = ttk.Label(
            handshake_frame,
            text="Status: Waiting...",
            style='Info.TLabel'
        )
        self.sender_handshake_status.pack()

        # Transfer
        transfer_frame = ttk.LabelFrame(sender_frame, text="4. Encrypt & Transfer", padding="10")
        transfer_frame.pack(fill=tk.X, pady=5)

        ttk.Button(
            transfer_frame,
            text="Encrypt & Send File",
            command=self.send_file,
            style='Success.TButton'
        ).pack(pady=5)

        self.sender_progress = ttk.Progressbar(transfer_frame, mode='determinate')
        self.sender_progress.pack(fill=tk.X, pady=5)

        self.sender_progress_label = ttk.Label(transfer_frame, text="", style='Info.TLabel')
        self.sender_progress_label.pack()

        # Reset
        ttk.Button(
            sender_frame,
            text="Reset (New Session)",
            command=self.reset_transfer,
            style='Danger.TButton'
        ).pack(pady=10)

    def create_receiver_panel(self, parent):
        """Create receiver panel"""
        receiver_frame = ttk.Frame(parent, padding="10")
        receiver_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)

        # Header
        ttk.Label(receiver_frame, text="RECEIVER", style='Header.TLabel').pack(anchor=tk.W)
        ttk.Separator(receiver_frame, orient=tk.HORIZONTAL).pack(fill=tk.X, pady=5)

        # Output directory
        output_frame = ttk.LabelFrame(receiver_frame, text="1. Output Directory", padding="10")
        output_frame.pack(fill=tk.X, pady=5)

        self.receiver_output_label = ttk.Label(
            output_frame,
            text=f"Saving to: {self.output_directory}",
            style='Info.TLabel'
        )
        self.receiver_output_label.pack(anchor=tk.W)

        ttk.Button(
            output_frame,
            text="Change Directory",
            command=self.select_output_directory,
            style='Primary.TButton'
        ).pack(pady=5)

        # Session info
        session_frame = ttk.LabelFrame(receiver_frame, text="2. Session Information", padding="10")
        session_frame.pack(fill=tk.X, pady=5)

        self.receiver_session_text = scrolledtext.ScrolledText(
            session_frame,
            height=6,
            width=40,
            font=('Courier', 9),
            state=tk.DISABLED
        )
        self.receiver_session_text.pack(fill=tk.BOTH)

        # Handshake status
        handshake_frame = ttk.LabelFrame(receiver_frame, text="3. Handshake Status", padding="10")
        handshake_frame.pack(fill=tk.X, pady=5)

        self.receiver_handshake_status = ttk.Label(
            handshake_frame,
            text="Status: Waiting for sender...",
            style='Info.TLabel'
        )
        self.receiver_handshake_status.pack()

        # Receive
        receive_frame = ttk.LabelFrame(receiver_frame, text="4. Receive & Decrypt", padding="10")
        receive_frame.pack(fill=tk.X, pady=5)

        self.receiver_progress = ttk.Progressbar(receive_frame, mode='determinate')
        self.receiver_progress.pack(fill=tk.X, pady=5)

        self.receiver_progress_label = ttk.Label(receive_frame, text="", style='Info.TLabel')
        self.receiver_progress_label.pack()

        # Verification
        verify_frame = ttk.LabelFrame(receiver_frame, text="5. Verification", padding="10")
        verify_frame.pack(fill=tk.X, pady=5)

        self.receiver_verify_text = scrolledtext.ScrolledText(
            verify_frame,
            height=6,
            width=40,
            font=('Courier', 9),
            state=tk.DISABLED
        )
        self.receiver_verify_text.pack(fill=tk.BOTH)

    def create_log_panel(self, parent):
        """Create bottom log panel"""
        log_frame = ttk.LabelFrame(parent, text="Transfer Log", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=8,
            font=('Courier', 9),
            wrap=tk.WORD
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # Configure tags for colored output
        self.log_text.tag_config('info', foreground='#3498db')
        self.log_text.tag_config('success', foreground='#27ae60')
        self.log_text.tag_config('error', foreground='#c0392b')
        self.log_text.tag_config('warning', foreground='#f39c12')

    def log(self, message, level='info'):
        """Add message to log"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        log_message = f"[{timestamp}] {message}\n"

        self.log_text.insert(tk.END, log_message, level)
        self.log_text.see(tk.END)

    def select_file(self):
        """Select file to transfer"""
        filepath = filedialog.askopenfilename(title="Select file to transfer")
        if filepath:
            self.selected_file = filepath
            filename = os.path.basename(filepath)
            filesize = os.path.getsize(filepath)
            self.sender_file_label.config(
                text=f"Selected: {filename} ({filesize} bytes)"
            )
            self.log(f"File selected: {filename} ({filesize} bytes)", 'info')

    def select_output_directory(self):
        """Select output directory"""
        directory = filedialog.askdirectory(title="Select output directory")
        if directory:
            self.output_directory = directory
            self.receiver_output_label.config(text=f"Saving to: {directory}")
            self.log(f"Output directory: {directory}", 'info')

    def update_session_info(self, text_widget, info_dict):
        """Update session info display"""
        text_widget.config(state=tk.NORMAL)
        text_widget.delete(1.0, tk.END)

        for key, value in info_dict.items():
            text_widget.insert(tk.END, f"{key}: {value}\n")

        text_widget.config(state=tk.DISABLED)

    def initiate_handshake(self):
        """Initiate DH key exchange handshake"""
        self.log("=" * 50, 'info')
        self.log("INITIATING NEW SECURE SESSION", 'warning')
        self.log("=" * 50, 'info')

        # Create new sessions for sender and receiver
        self.sender_session = self.transfer_protocol.create_session()
        self.receiver_session = self.transfer_protocol.create_session()

        self.log(f"Sender session created: {self.sender_session.session_id}", 'info')
        self.log(f"Receiver session created: {self.receiver_session.session_id}", 'info')

        # Exchange public keys
        self.log("Performing Diffie-Hellman key exchange...", 'info')

        sender_public = self.sender_session.dh.get_public_key()
        receiver_public = self.receiver_session.dh.get_public_key()

        self.log(f"Sender public key: {hex(sender_public)[:50]}...", 'info')
        self.log(f"Receiver public key: {hex(receiver_public)[:50]}...", 'info')

        # Complete handshake
        sender_response = self.transfer_protocol.sender_handshake(
            self.sender_session,
            receiver_public
        )
        receiver_response = self.transfer_protocol.receiver_handshake(
            self.receiver_session,
            sender_public
        )

        self.log("Handshake completed successfully!", 'success')
        self.log(f"Shared encryption key derived (both parties have same key)", 'success')

        # Update UI
        self.sender_handshake_status.config(text="Status: Handshake Complete ✓")
        self.receiver_handshake_status.config(text="Status: Handshake Complete ✓")

        # Update session info
        sender_info = {
            "Session ID": self.sender_session.session_id[-20:],
            "Status": self.sender_session.status,
            "Public Key": f"{hex(sender_public)[:30]}...",
            "Shared Key": f"{self.sender_session.shared_key.hex()[:30]}..." if self.sender_session.shared_key else "None"
        }

        receiver_info = {
            "Session ID": self.receiver_session.session_id[-20:],
            "Status": self.receiver_session.status,
            "Public Key": f"{hex(receiver_public)[:30]}...",
            "Shared Key": f"{self.receiver_session.shared_key.hex()[:30]}..." if self.receiver_session.shared_key else "None"
        }

        self.update_session_info(self.sender_session_text, sender_info)
        self.update_session_info(self.receiver_session_text, receiver_info)

        messagebox.showinfo(
            "Handshake Complete",
            "Diffie-Hellman key exchange completed!\n\n"
            "Both parties now share a secret encryption key.\n"
            "You can now transfer the file securely."
        )

    def send_file(self):
        """Encrypt and send file"""
        if not self.selected_file:
            messagebox.showerror("Error", "Please select a file first!")
            return

        if not self.sender_session or self.sender_session.status != "HANDSHAKE_COMPLETE":
            messagebox.showerror("Error", "Please complete handshake first!")
            return

        # Run transfer in a separate thread
        thread = threading.Thread(target=self._send_file_thread, daemon=True)
        thread.start()

    def _send_file_thread(self):
        """Thread for file transfer"""
        try:
            # Encrypt file
            self.log("=" * 50, 'info')
            self.log("ENCRYPTING AND TRANSFERRING FILE", 'warning')
            self.log("=" * 50, 'info')

            def sender_progress(message, progress):
                self.root.after(0, lambda: self.sender_progress.config(value=progress))
                self.root.after(0, lambda: self.sender_progress_label.config(text=message))
                self.log(f"Sender: {message}", 'info')

            encrypt_result = self.transfer_protocol.encrypt_and_prepare_file(
                self.sender_session,
                self.selected_file,
                sender_progress
            )

            self.log(f"File encrypted: {encrypt_result['num_chunks']} chunks", 'success')
            self.log(f"Original checksum: {encrypt_result['checksum'][:32]}...", 'info')

            # Transfer file
            def receiver_progress(message, progress):
                self.root.after(0, lambda: self.receiver_progress.config(value=progress))
                self.root.after(0, lambda: self.receiver_progress_label.config(text=message))
                self.log(f"Receiver: {message}", 'info')

            transfer_result = self.transfer_protocol.transfer_file(
                self.sender_session,
                self.receiver_session,
                receiver_progress
            )

            self.log(f"Transfer complete: {transfer_result['chunks_transferred']} chunks", 'success')

            # Decrypt and verify
            output_filename = f"received_{os.path.basename(self.selected_file)}"
            output_path = os.path.join(self.output_directory, output_filename)

            verify_result = self.transfer_protocol.decrypt_and_verify_file(
                self.receiver_session,
                output_path,
                receiver_progress
            )

            if verify_result['checksum_valid']:
                self.log("✓ CHECKSUM VERIFICATION SUCCESSFUL!", 'success')
                self.log(f"File saved to: {output_path}", 'success')

                verify_info = {
                    "Status": "SUCCESS ✓",
                    "Checksum": "VALID",
                    "Expected": verify_result['expected_checksum'][:32] + "...",
                    "Computed": verify_result['computed_checksum'][:32] + "...",
                    "Output": output_filename
                }

                self.root.after(0, lambda: self.update_session_info(
                    self.receiver_verify_text,
                    verify_info
                ))

                self.root.after(0, lambda: messagebox.showinfo(
                    "Transfer Complete",
                    f"File transferred successfully!\n\n"
                    f"Checksum verified: ✓\n"
                    f"Saved to: {output_path}"
                ))
            else:
                self.log("✗ CHECKSUM VERIFICATION FAILED!", 'error')
                self.root.after(0, lambda: messagebox.showerror(
                    "Verification Failed",
                    "File transfer completed but checksum verification failed!\n"
                    "The file may be corrupted."
                ))

        except Exception as e:
            self.log(f"Error during transfer: {str(e)}", 'error')
            self.root.after(0, lambda: messagebox.showerror("Error", str(e)))

    def reset_transfer(self):
        """Reset for new transfer with fresh keys (forward secrecy)"""
        self.log("=" * 50, 'warning')
        self.log("RESETTING SESSION - FORWARD SECRECY", 'warning')
        self.log("All keys will be regenerated for next transfer", 'warning')
        self.log("=" * 50, 'warning')

        self.sender_session = None
        self.receiver_session = None
        self.selected_file = None

        # Reset UI
        self.sender_file_label.config(text="No file selected")
        self.sender_handshake_status.config(text="Status: Waiting...")
        self.receiver_handshake_status.config(text="Status: Waiting for sender...")
        self.sender_progress.config(value=0)
        self.receiver_progress.config(value=0)
        self.sender_progress_label.config(text="")
        self.receiver_progress_label.config(text="")

        # Clear text widgets
        for widget in [self.sender_session_text, self.receiver_session_text, self.receiver_verify_text]:
            widget.config(state=tk.NORMAL)
            widget.delete(1.0, tk.END)
            widget.config(state=tk.DISABLED)

        self.log("Session reset complete. Ready for new transfer.", 'success')


def main():
    """Main entry point"""
    root = tk.Tk()
    app = SecureFileTransferGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
