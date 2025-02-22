from scapy.all import rdpcap, IP
import math
import tkinter as tk
from tkinter import filedialog, messagebox

# Variables to store packet counts
packet_count = 0
malicious_received_count = 0
normal_received_count = 0
skipped_count = 0
received_count = 0
sent_count = 0
previous_timestamp = None  # To store the timestamp of the last packet

# Prior probabilities for received packets
P_normal_received = 0.9
P_malicious_received = 0.1

# Mean and standard deviation for packet size (based on historical data)
mean_size_normal_received = 500.0
std_dev_size_normal_received = 200.0
mean_size_malicious_received = 80.0
std_dev_size_malicious_received = 50.0

# Mean and standard deviation for time delay (based on historical data)
mean_delay_normal = 0.1  # Mean time delay for normal packets (in seconds)
std_dev_delay_normal = 0.05  # Standard deviation for normal packets
mean_delay_malicious = 0.00001  # Mean time delay for malicious packets
std_dev_delay_malicious = 0.0005  # Standard deviation for malicious packets

# Function to calculate the Gaussian probability density function (PDF)
def gaussian_pdf(x, mean, std_dev):
    epsilon = 1e-10  # a very small value to avoid division by zero
    std_dev = max(std_dev, epsilon)  # ensure std_dev is not less than epsilon
    exponent = math.exp(-((float(x) - mean) ** 2) / (2 * (std_dev ** 2)))
    return (1 / (math.sqrt(2 * math.pi) * std_dev)) * exponent

# Calculate likelihoods for packet size
def calculate_likelihoods(packet_size):
    L_size_normal = gaussian_pdf(packet_size, mean_size_normal_received, std_dev_size_normal_received)
    L_size_malicious = gaussian_pdf(packet_size, mean_size_malicious_received, std_dev_size_malicious_received)
    return L_size_normal, L_size_malicious

# Updated Naive Bayes classification with packet size and time delay
def is_malicious(packet_size, time_delay):
    # Calculate likelihoods for packet size
    L_size_normal, L_size_malicious = calculate_likelihoods(packet_size)

    # Calculate likelihoods for time delay
    L_delay_normal = gaussian_pdf(time_delay, mean_delay_normal, std_dev_delay_normal)
    L_delay_malicious = gaussian_pdf(time_delay, mean_delay_malicious, std_dev_delay_malicious)

    # Add a small epsilon to avoid division by zero
    epsilon = 1e-10
    denominator = (
        (L_size_normal * L_delay_normal * P_normal_received)
        + (L_size_malicious * L_delay_malicious * P_malicious_received)
    )
    denominator = max(denominator, epsilon)  # Avoid zero denominator

    # Combine likelihoods for both features using Naive Bayes
    posterior_normal = (
        L_size_normal * L_delay_normal * P_normal_received
    ) / denominator

    posterior_malicious = (
        L_size_malicious * L_delay_malicious * P_malicious_received
    ) / denominator

    # Classify the packet
    return posterior_malicious > posterior_normal

# Update the packet_callback function to include time delay in the classification
def packet_callback(packet):
    global packet_count, malicious_received_count, normal_received_count, skipped_count, received_count, sent_count, previous_timestamp

    packet_count += 1

    # Check if the packet has an IP layer
    if IP in packet:
        packet_size = len(packet)
        destination_ip = packet[IP].dst
        current_timestamp = packet.time  # Timestamp of the current packet

        # Determine if the packet is received (assuming local network is 10.20.30.101)
        is_received = destination_ip.startswith("10.20.30.101")

        if is_received:
            received_count += 1
            if previous_timestamp is not None:
                time_delay = current_timestamp - previous_timestamp
                time_delay = max(time_delay, 1e-10)  # Prevent division by zero
            else:
                time_delay = float("inf")  # For the first packet, assume a very high time delay

            # Apply Naive Bayes to classify based on packet size and time delay
            malicious = is_malicious(packet_size, time_delay)
            if malicious:
                malicious_received_count += 1
            else:
                normal_received_count += 1

            previous_timestamp = current_timestamp  # Update previous timestamp for next packet
        else:
            sent_count += 1
    else:
        skipped_count += 1  # Packet without IP layer

# GUI for file selection and packet analysis
def start_analysis():
    global packet_count, malicious_received_count, normal_received_count, skipped_count, received_count, sent_count, previous_timestamp

    # Reset counters
    packet_count = malicious_received_count = normal_received_count = skipped_count = received_count = sent_count = 0
    previous_timestamp = None

    # Open file dialog to select a PCAP file
    file_path = filedialog.askopenfilename(title="Select PCAP File", filetypes=[("PCAP Files", "*.pcap"), ("All Files", "*.*")])

    if not file_path:
        messagebox.showinfo("Info", "No file selected!")
        return

    try:
        packets = rdpcap(file_path)

        # Analyze packets
        for packet in packets:
            packet_callback(packet)

        # Display results
        result_message = (
            f"Total packets analyzed: {packet_count}\n"
            f"Total packets received: {received_count}\n"
            f"Total normal packets received: {normal_received_count}\n"
            f"Total malicious packets received: {malicious_received_count}\n"
            f"Skipped (non-IP) packets: {skipped_count}\n"
            f"Total packets classified: {normal_received_count + malicious_received_count}"
        )
        messagebox.showinfo("Analysis Complete", result_message)
    except Exception as e:
        messagebox.showerror("Error", f"Failed to analyze packets: {e}")

# Main function to create the GUI
def main():
    root = tk.Tk()
    root.title("Malicious Network Traffic Identification System")

    label = tk.Label(root, text="Select a PCAP file to analyze for malicious traffic:")
    label.pack(pady=10)

    analyze_button = tk.Button(root, text="Start Analysis", command=start_analysis)
    analyze_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()
