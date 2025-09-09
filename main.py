# Imports, tkinter is for GUI, sounddevice/soundfile is for handling audio, OS is for file manipulation, time is to track time, numpy is for math
# Cryptography handles the encryption and key exchange
# Code by Mackenzie Nisbet 0878135
import tkinter as tk
from tkinter import filedialog, ttk
import sounddevice as sd
import soundfile as sf
import os
import time
import numpy as np
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# User class holds all attributes and methods related to Diffie Hellman
class User:
    users_instances = []  # List to store user instances

    # Goes through user instance list and prints out names and instance id's (used for debugging)
    @classmethod
    def print_all_user_instances(cls):
        for user_instance in cls.users_instances:
            user = user_instance['instance']
            print(f"{user.name} instance:")
            print(f"  Public Key: {user.get_public_key()}")
            print("\n")

    # Start of individual user methods, takes user name, root window, list of input/output devices, and shared DH parameters
    def __init__(self, name, main_window, input_devices, output_devices, shared_parameters):
        self.name = name
        self.sample_rate = 44100 # Default Sample rate
        self.channels = 2  # Number of audio channels
        if main_window:
            self.root = tk.Toplevel(main_window)
        else:
            self.root = tk.Tk()
        # Sets the names of the window + size
        self.root.title(self.name)
        self.root.geometry("400x550")

        # Status labels used to show success/failure of recording, encryption, decryption
        self.snr_status_label = tk.Label(self.root, text="")
        self.snr_status_label.pack()
        self.encryption_status_label = tk.Label(self.root, text="")
        self.encryption_status_label.pack()
        self.decryption_status_label = tk.Label(self.root, text="")
        self.decryption_status_label.pack()
        
        # Use the shared parameters for Diffie-Hellman
        # The shared keys could be stored as a list on creation, but that poses security issues and isn't really necessary
        # Updating the shared key every time the function is called also allows us to demonstrate the MITM attack
        self.private_key = shared_parameters.generate_private_key()
        self.public_key = self.private_key.public_key()
        self.shared_key = None

        # Append user instance to the list
        User.users_instances.append({"name": self.name, "instance": self})

        # ... GUI elements ... #
        # Label of the user's name
        self.username_label = tk.Label(self.root, text=self.name)
        self.username_label.pack()

        # Shows a list of input devices, lets the user choose
        self.input_device_label = tk.Label(self.root, text="Select Input Device:")
        self.input_device_label.pack()
        self.selected_input_device = tk.StringVar(self.root)
        self.selected_input_device.set(input_devices[0] if input_devices else "No Input Devices")
        self.input_device_menu = tk.OptionMenu(self.root, self.selected_input_device, *input_devices)
        self.input_device_menu.pack()

        # Shows a list of output devices, lets the user choose
        self.output_device_label = tk.Label(self.root, text="Select Output Device:")
        self.output_device_label.pack()
        self.selected_output_device = tk.StringVar(self.root)
        self.selected_output_device.set(output_devices[0] if output_devices else "No Output Devices")
        self.output_device_menu = tk.OptionMenu(self.root, self.selected_output_device, *output_devices)
        self.output_device_menu.pack()

        # Sets duration of audio recording
        self.duration_label = tk.Label(self.root, text="Duration (seconds):")
        self.duration_label.pack()
        self.duration_entry = tk.Entry(self.root)
        self.duration_entry.insert(0, "1.0")  # Default duration
        self.duration_entry.pack()

        # Add a label and entry for the sample rate
        tk.Label(self.root, text="Sample Rate:").pack()
        self.sample_rate_entry = tk.Entry(self.root)
        self.sample_rate_entry.insert(0, str(self.sample_rate))  # Default sample rate
        self.sample_rate_entry.pack()
        
        # Lets use choose the audio file to perform operations on
        self.filename_label = tk.Label(self.root, text="Enter Filename:")
        self.filename_label.pack()
        self.filename_entry = tk.Entry(self.root)
        self.filename_entry.insert(0, f"{self.name.lower()}_captured_audio.wav")
        self.filename_entry.pack()

        # Buttons follow format: button text, other arguments, function (method) called. Most attributes/variables are directly referenced from within method
        self.capture_button = tk.Button(self.root, text="Capture Audio", command=self.capture_audio)
        self.capture_button.pack()

        self.choose_file_button = tk.Button(self.root, text="Choose Audio File", command=self.choose_audio_file)
        self.choose_file_button.pack()

        self.play_button = tk.Button(self.root, text="Play Audio", command=self.play_audio)
        self.play_button.pack()

        self.send_file_button = tk.Button(self.root, text="Send Audio File", command=self.send_audio_file)
        self.send_file_button.pack()

        self.choose_public_key_button = tk.Button(self.root, text="Choose public key", command=self.choose_public_key)
        self.choose_public_key_button.pack()
        
        self.encrypt_audio_button = tk.Button(self.root, text="Encrypt Audio File", command=self.encrypt_audio)
        self.encrypt_audio_button.pack()
        
        self.decrypt_audio_button = tk.Button(self.root, text="Decrypt Audio File", command=self.decrypt_audio)
        self.decrypt_audio_button.pack()

        self.shared_with_label = tk.Label(self.root, text="")
        self.shared_with_label.pack()

    # Lets Tkinter start running the application
    def start(self):
        self.root.mainloop()
    
    # Updates the labels of the current file, and the user it was shared with
    def update_shared_with_label(self, user):
        self.shared_with_label.config(text=f"Last shared with: {user}")
    
    def update_current_filename_label(self, filename):
        self.filename_label.config(text=f"Current Filename: {filename}")
    
    # Calculates SNR, takes data from an audio file and returns the SNR
    def calculate_quantization_snr(self, audio_data):
        # Calculate Quantization SNR in dB with power values
        signal_power = np.sum(audio_data**2)
        noise_power = np.sqrt(np.sum((audio_data - np.mean(audio_data))**2) / 2.0)
        quantization_snr_db = 10 * np.log10(signal_power / noise_power)
        return quantization_snr_db
    
    # Method used to capture the recording
    def capture_audio(self):
        try:
            # Hard coded variables since 40's the requirement 
            # I tried implementing multiple attempts 
            target_snr = 40
            max_attempts = 1
            current_attempt = 1

            # Updates the SNR label in case it's less than the min amount
            def update_snr_status_label(snr, attempt):
                self.snr_status_label.config(text=f"Quantization SNR: {snr:.2f} dB (Attempt {attempt})")
                self.root.update_idletasks()

            # Attempt to implement multiple tries untilt he SNR is right
            while current_attempt <= max_attempts:
                # Gets the list of input devices to record
                self.duration = float(self.duration_entry.get())
                input_device_id = [device['index'] for device in sd.query_devices() if
                                   device['name'] == self.selected_input_device.get()][0]
                filename = self.filename_entry.get()

                # Get the sample rate from the entry field
                sample_rate_entry_value = self.sample_rate_entry.get()
                self.sample_rate = int(sample_rate_entry_value) if sample_rate_entry_value.isdigit() else self.sample_rate

                # Record function using the chosen sample rate
                audio_data = sd.rec(int(self.duration * self.sample_rate), samplerate=self.sample_rate,
                                    channels=self.channels, dtype='int16', device=input_device_id)
                sd.wait()
                sd.default.device = input_device_id
                sf.write(filename, audio_data, self.sample_rate)

                # Calculates the SNR and updates the label
                snr = self.calculate_quantization_snr(audio_data)
                self.root.after(0, update_snr_status_label, snr, current_attempt)

                # If the recorded SNR is lower than the target SNR try again
                if snr >= target_snr:
                    print(f"Audio captured and saved as {filename}")
                    self.root.after(0, self.snr_status_label.config, {"text": ""})
                    break
                else:
                    print(f"Quantization SNR is below {target_snr} dB. Recapturing audio...")
                    current_attempt += 1

            # Records the last attempt even if the last try failed, also deletes the message after 3 seconds
            if current_attempt > max_attempts:
                print(f"Unable to achieve the target Quantization SNR after {max_attempts} attempts.")
                self.root.after(0, self.snr_status_label.config,
                                {"text": f"Quantization SNR ({snr:.2f} dB) below target ({target_snr} dB). Last attempt recorded.",
                                 "fg": "red"})
                self.root.after(3000, lambda: self.snr_status_label.config(text=""))
        
        except Exception as e:
            print(f"Error capturing audio: {e}")

    # Method to play the audio, uses the soundfile library to read and play the audio, prints error if fails
    def play_audio(self):
        try:
            # Gets output devices
            filename = self.filename_entry.get()
            output_device_id = [device['index'] for device in sd.query_devices() if
                                device['name'] == self.selected_output_device.get()][0]
            audio_data, sample_rate = sf.read(filename, dtype='int16')
            # Plays the recorded audio at the recorded sample rate
            sd.play(audio_data, sample_rate, device=output_device_id)
            sd.wait()
            print(f"Audio played from {filename}")
        except Exception as e:
            print(f"Error playing audio: {e}")

    # Method to choose the audio file, saves in the filename attribute, one different filename for every user instance
    def choose_audio_file(self):
        file_path = filedialog.askopenfilename(initialdir="./", title="Select Audio File",
                                               filetypes=[("Audio Files", "*.wav;*.flac;*.mp3")])
        if file_path:
            self.filename_entry.delete(0, tk.END)
            self.filename_entry.insert(0, file_path)
            self.update_current_filename_label(file_path)
            
    # Method to send the currently selected audio file to the other users, can send encrypted or unencrypted files            
    def send_audio_file(self):
        try:
            filename = self.filename_entry.get()
            if os.path.exists(filename):
                # Gets list of users from user_instance class dictionary, sets their filename attribute to the file
                recipients = [user_instance['instance'] for user_instance in User.users_instances if user_instance['name'] != self.name]
                for recipient in recipients:
                    recipient.set_received_filename(filename)

                print(f"Audio file sent to {', '.join([recipient.name for recipient in recipients])}: {filename}")
            else:
                print(f"File does not exist: {filename}")
        except Exception as e:
            print(f"Error sending audio file: {e}")

    # Updates the current file and label when this function is called
    def set_received_filename(self, filename):
        self.filename_entry.delete(0, tk.END)
        self.filename_entry.insert(0, filename)
        self.update_current_filename_label(filename)

    # Gets another users public key
    def get_public_key(self):
        # Return the public key in a serialized form
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    # Performs the key exchange between two users
    def exchange_keys(self, selected_user):
        if selected_user and selected_user != self:
            # Perform key exchange using the private key and the other user's public key for both users
            self.shared_key = self.private_key.exchange(selected_user.public_key)
            selected_user.shared_key = selected_user.private_key.exchange(self.public_key)
            self.update_shared_with_label(selected_user.name)
            selected_user.update_shared_with_label(self.name)
        else:
            print("Invalid user selection.")

    # Allows the user to choose whose key they want to encrypt with 
    def choose_public_key(self):
        # Creates a dialog box to choose another user
        choose_user_dialog = tk.Toplevel(self.root)
        choose_user_dialog.title("Choose User")
        choose_user_dialog.geometry("200x150")

        label = tk.Label(choose_user_dialog, text="Choose another user:")
        label.pack()

        self.user_choice = tk.StringVar(choose_user_dialog)
        self.user_choice.set("")  # default choice

        # OptionMenu to choose another user
        user_menu = tk.OptionMenu(choose_user_dialog, self.user_choice, *["Alice", "Bob", "Jack"])
        user_menu.pack()

        # Creates the button used to confirm the selection
        exchange_button = tk.Button(choose_user_dialog, text="Exchange Keys", command=lambda: self.perform_key_exchange(choose_user_dialog))
        exchange_button.pack()

    # Calls the key exchange function and updates the labels
    def perform_key_exchange(self, choose_user_dialog):
        selected_user_name = self.user_choice.get()
        selected_user = next(
            (user_instance['instance'] for user_instance in User.users_instances if user_instance['name'] == selected_user_name),
            None
        )
        # Handles the success update label
        if selected_user:
            try:
                self.exchange_keys(selected_user)
                selected_user.exchange_keys(self)
                # If the key exchange completes without errors, show success message
                success_message = f"Key exchange with {selected_user_name} successful!"
                success_label = tk.Label(choose_user_dialog, text=success_message)
                success_label.pack()
            except Exception as e:
                # Handle the error in case of key exchange failure
                print(f"Key exchange error: {e}")

    # Audio encryption function
    def encrypt_audio(self):
        # If there is a set shared key allow the encryption (check DH parameter setup for explanation why it's done like this)
        if self.shared_key is None:
            raise ValueError("Key exchange not performed.")
        try:
            # Read audio data from the file
            filename = self.filename_entry.get()
            with open(filename, 'rb') as file:
                audio_data = file.read()

            # Pad the audio data to match the block size of AES
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            audio_data_padded = padder.update(audio_data) + padder.finalize()

            # Derive an AES key from the shared key using HKDF
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # AES-256 requires a 256-bit key
                salt=None,
                info=b'diffie-hellman-audio-encryption',
                backend=default_backend()
            ).derive(self.shared_key)

            # Encypy the audio data
            cipher = Cipher(algorithms.AES(derived_key), modes.CFB(b'\0' * 16), backend=default_backend())
            encryptor = cipher.encryptor()
            encrypted_audio_data = encryptor.update(audio_data_padded) + encryptor.finalize()

            # Generate the output
            output_filename = f"{os.path.splitext(filename)[0]}_encrypted.wav"

            # Write the encrypted audio data to the new file
            with open(output_filename, 'wb') as output_file:
                output_file.write(encrypted_audio_data)

            print(f"Audio encrypted and saved as {output_filename}")

            # Display success message for 3 seconds
            self.encryption_status_label.config(text="Audio encrypted successfully.", fg="green")
            self.root.after(3000, lambda: self.encryption_status_label.config(text=""))  # Remove after 3 seconds

        except Exception as e:
            # Display error message for 3 seconds
            self.encryption_status_label.config(text=f"Error encrypting audio: {e}", fg="red")
            self.root.after(3000, lambda: self.encryption_status_label.config(text=""))  # Remove after 3 seconds

    # Audio decryption function
    def decrypt_audio(self):
        if self.shared_key is None:
            raise ValueError("Key exchange not performed.")
        
        try:
        
            filename = self.filename_entry.get()
            # Read the encrypted audio data from the file
            with open(filename, 'rb') as file:
                encrypted_audio_data = file.read()

            # Derive an AES key from the shared key using HKDF
            derived_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # AES-256 requires a 256-bit key
                salt=None,
                info=b'diffie-hellman-audio-encryption',
                backend=default_backend()
            ).derive(self.shared_key)

            # Decrypt the audio
            cipher = Cipher(algorithms.AES(derived_key), modes.CFB(b'\0' * 16), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_audio_data_padded = decryptor.update(encrypted_audio_data) + decryptor.finalize()

            # Manually remove padding based on the block size
            block_size = algorithms.AES.block_size // 8
            padding_size = decrypted_audio_data_padded[-1]

            if padding_size > block_size or padding_size == 0:
                raise ValueError("Invalid padding bytes.")

            decrypted_audio_data = decrypted_audio_data_padded[:-padding_size]

            # Generate the output filename
            output_filename = f"{os.path.splitext(filename)[0]}_decrypted.wav"

            # Write the decrypted audio data to a new .wav file
            with open(output_filename, 'wb') as file:
                file.write(decrypted_audio_data)

            print(f"Audio decrypted and saved as {output_filename}")

            # Display success message for 3 seconds
            self.decryption_status_label.config(text="Audio decrypted successfully.", fg="green")
            self.root.after(3000, lambda: self.decryption_status_label.config(text=""))  # Remove after 3 seconds

        except Exception as e:
            # Display error message for 3 seconds
            self.decryption_status_label.config(text=f"Error decrypting audio: {e}", fg="red")
            self.root.after(3000, lambda: self.decryption_status_label.config(text=""))  # Remove after 3 seconds

# Class that handles the time calculation and can be used to display a files SNR
class TimeWindow:
    def __init__(self, root, shared_parameters_generation_time, user_instances_creation_time):
        self.root = root
        self.time_window = tk.Toplevel(self.root)
        self.time_window.title("Time + SNR")
        self.time_window.geometry("400x250")

        # Displays the creation time, shared parameters generation time is the important one since that's the time it takes to generate keys
        ttk.Label(self.time_window, text=f"Shared Parameters Generation Time: {shared_parameters_generation_time:.3f} seconds").pack()
        ttk.Label(self.time_window, text=f"User Instances Creation Time: {user_instances_creation_time:.2f} seconds").pack()

        self.chosen_file_label = ttk.Label(self.time_window, text="")
        self.chosen_file_label.pack()

        self.snr_label = ttk.Label(self.time_window, text="")
        self.snr_label.pack()

        self.link_capacity_label = ttk.Label(self.time_window, text="")
        self.link_capacity_label.pack()

        # Allows the user to choose a file for SNR analysis
        ttk.Button(self.time_window, text="Choose File", command=self.choose_file_and_calculate).pack()
        ttk.Button(self.time_window, text="Clear", command=self.clear_labels).pack()

    # Function to calculate the SNR using the power formula
    def calculate_snr(self, audio_data):
        signal_power = np.sum(audio_data**2)
        noise_power = np.sqrt(np.sum((audio_data - np.mean(audio_data))**2) / 2.0)
        snr_db = 10 * np.log10(signal_power / noise_power)
        return snr_db

    # Function to calculate the link capacity
    def calculate_link_capacity(self, filename, duration):
        file_size_bits = os.path.getsize(filename) * 8
        link_capacity = file_size_bits / duration
        return link_capacity

    # Choose a file and run the calculation functions
    def choose_file_and_calculate(self):
        file_path = filedialog.askopenfilename(initialdir="./", title="Select Audio File",
                                               filetypes=[("Audio Files", "*.wav;*.flac;*.mp3")])

        if file_path:
            self.chosen_file_label.config(text=f"Chosen File: {file_path}")

            # Read audio data from the chosen file
            audio_data, sample_rate = sf.read(file_path, dtype='int16')

            # Calculate SNR
            snr = self.calculate_snr(audio_data)
            self.snr_label.config(text=f"SNR: {snr:.2f} dB")

            # Calculate link capacity
            duration = len(audio_data) / sample_rate
            link_capacity = self.calculate_link_capacity(file_path, duration)
            self.link_capacity_label.config(text=f"Link Capacity: {link_capacity / 1000:.2f} Kbps")

    # Clears the labels so it can be run again (might not be necessary since I have the labels being overwritten right now)
    def clear_labels(self):
        self.chosen_file_label.config(text="")
        self.snr_label.config(text="")
        self.link_capacity_label.config(text="")

# Main loop
def main():
    root_sender = tk.Tk()

    # Stores a list of the computers input and output devices
    input_devices = [device['name'] for device in sd.query_devices() if device['max_input_channels'] > 0]
    output_devices = [device['name'] for device in sd.query_devices() if device['max_output_channels'] > 0]

    # Measure the time elapsed for shared parameters generation
    start_time = time.time()
    shared_parameters = dh.generate_parameters(generator=2, key_size=2048)
    shared_parameters_generation_time = time.time() - start_time

    # Measure the time elapsed for creating user instances
    start_time = time.time()
    
    # Creates the user instances: User name, main window, list of input devices, list of output devices, shared deffie hellman parameters
    alice_instance = User("Alice", root_sender, input_devices, output_devices, shared_parameters)
    bob_instance = User("Bob", root_sender, input_devices, output_devices, shared_parameters)
    jack_instance = User("Jack", root_sender, input_devices, output_devices, shared_parameters)
    user_instances_creation_time = time.time() - start_time

    # Print user instances
    User.print_all_user_instances()

    # Display the time elapsed in a separate window
    time_window = TimeWindow(root_sender, shared_parameters_generation_time, user_instances_creation_time)

    root_sender.mainloop()

# Run the program
if __name__ == "__main__":
    main()