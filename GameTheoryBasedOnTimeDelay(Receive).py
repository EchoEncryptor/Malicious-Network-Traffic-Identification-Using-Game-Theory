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
previous_timestamp = None

# Prior probabilities
P_normal_received = 0.9
P_malicious_received = 0.1

# Mean and standard deviation for time delay (based on historical data)
mean_delay_normal_received = 0.1  # seconds
std_dev_delay_normal_received = 0.05
mean_delay_malicious_received = 0.00001  # seconds
std_dev_delay_malicious_received = 0.0005

# Function to calculate the Gaussian probability density function (PDF)
def gaussian_pdf(x, mean, std_dev):
    epsilon = 1e-10  # a very small value to avoid division by zero
    std_dev = max(std_dev, epsilon)  # ensure std_dev is not less than epsilon
    exponent = math.exp(-((float(x) - mean) ** 2) / (2 * (std_dev ** 2)))
    return (1 / (math.sqrt(2 * math.pi) * std_dev)) * exponent

# Likelihood calculation based on time delay
def calculate_likelihood(time_delay):
    L_delay_normal = gaussian_pdf(time_delay, mean_delay_normal_received, std_dev_delay_normal_received)
    L_delay_malicious = gaussian_pdf(time_delay, mean_delay_malicious_received, std_dev_delay_malicious_received)
    return L_delay_normal, L_delay_malicious

# Bayes Theorem to determine if a packet is malicious
def is_malicious(time_delay):
    L_normal, L_malicious = calculate_likelihood(time_delay)
    evidence = L_normal * P_normal_received + L_malicious * P_malicious_received
    if evidence == 0:
        return False

    # Calculate posterior probabilities
    P_normal_given = (L_normal * P_normal_received) / evidence
    P_malicious_given = (L_malicious * P_malicious_received) / evidence

    # Threshold for deciding if a packet is malicious
    return P_malicious_given > 0.5

# Define the IDS function
def packet_callback(packet):
    global packet_count, malicious_received_count, normal_received_count, skipped_count, received_count, sent_count, previous_timestamp

    packet_count += 1

    # Check if the packet has an IP layer
    if IP in packet:
        current_timestamp = packet.time  # Get packet timestamp
        time_delay = (current_timestamp - previous_timestamp) if previous_timestamp else mean_delay_normal_received
        previous_timestamp = current_timestamp

        destination_ip = packet[IP].dst

        # Determine if the packet is received (assuming local network is 10.20.30.101)
        is_received = destination_ip.startswith("10.20.30.101")

        if is_received:
            received_count += 1
            malicious = is_malicious(time_delay)
            if malicious:
                malicious_received_count += 1
            else:
                normal_received_count += 1
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
            f"Total packets sent: {sent_count}\n"
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
    root.geometry("300x100")
    
    label = tk.Label(root, text="Select a PCAP file to analyze for malicious traffic:")
    label.pack(pady=10)

    analyze_button = tk.Button(root, text="Start Analysis", command=start_analysis)
    analyze_button.pack(pady=10)

    root.mainloop()

if __name__ == "__main__":
    main()
