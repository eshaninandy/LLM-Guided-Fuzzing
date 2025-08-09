import os
import threading
import time
import socket
import serial
from boofuzz import (
    Session, Target, s_initialize, s_block_start, s_block_end,
    s_string, s_delim, s_get, TCPSocketConnection
)

# === Configuration ===
TARGET_IP = "192.168.2.2"
TARGET_PORT = 5515

ARDUINO_PORT = "/dev/tty.usbmodem11101"
RELAY_CHANNEL = 1

CHECK_INTERVAL = 5          # seconds between port checks
DOWN_TIMEOUT = 90           # seconds of continuous TCP-port downtime to call it a crash
PI_BOOT_WAIT = 30           # wait after power-on before starting fuzzing

# === Payloads ===
PREFIXES = ["ping", "exec", "run", "exit", "get", "set", "info", "config", "update", "version"]
PAYLOADS = [
    "reb00t", "rebo ot", "REBOOT", "Reb\toot", "re\\boot",
    "shutDOWN", "sh\tutdown", "shut_down", "sHuTdOwN",
    "halt", "H@LT", "ha1t", "h\\alt", "h\u0061lt"
]

# === Flags and State ===
stop_monitor = threading.Event()
crash_detected = threading.Event()

# === Arduino / Relay helpers ===
def open_arduino(port, baud=9600, open_wait=2.0):
    print("[*] Connecting to Arduino...")
    ser = serial.Serial(port, baud)
    time.sleep(open_wait)  # allow Arduino to reset
    print("[*] Connected to Arduino.")
    return ser

def relay_on(ser, channel):
    ser.write(f"ON{channel}\n".encode())

def relay_off(ser, channel):
    ser.write(f"OFF{channel}\n".encode())

# === TCP Port Health Check ===
def tcp_port_is_up(ip, port, timeout=2.0) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False

def port_monitor(ip, port, down_timeout, check_interval, arduino_ser, relay_channel):
    """
    Powers off the Pi if TCP port stays DOWN continuously for `down_timeout` seconds.
    Resets the timer as soon as the port is reachable again.
    """
    print("[*] TCP port monitor started.")
    last_up = time.time()  # start optimistic; will be corrected on first check
    was_up = None

    while not stop_monitor.is_set():
        up = tcp_port_is_up(ip, port, timeout=2.0)

        now = time.time()
        if up:
            if was_up is False:
                print("[*] Target port restored. Resetting downtime timer.")
            last_up = now
            was_up = True
        else:
            was_up = False
            down_for = now - last_up
            print(f"[!] Target port down for {int(down_for)}s")
            if down_for >= down_timeout:
                print("[!] Target port down continuously beyond threshold. Assuming crash.")
                crash_detected.set()
                try:
                    relay_off(arduino_ser, relay_channel)
                    print("[!] Pi powered OFF.")
                finally:
                    os._exit(0)  # ensure immediate termination to avoid boofuzz hanging

        time.sleep(check_interval)

# === Main ===
def main():
    # Arduino / power
    arduino = open_arduino(ARDUINO_PORT, 9600, open_wait=2.0)

    print("[*] Powering ON Raspberry Pi...")
    relay_on(arduino, RELAY_CHANNEL)
    time.sleep(PI_BOOT_WAIT)

    # Start TCP port monitor
    monitor_thread = threading.Thread(
        target=port_monitor,
        args=(TARGET_IP, TARGET_PORT, DOWN_TIMEOUT, CHECK_INTERVAL, arduino, RELAY_CHANNEL),
        daemon=True,
    )
    monitor_thread.start()

    # === Fuzzing Setup ===
    connection = TCPSocketConnection(TARGET_IP, TARGET_PORT)
    session = Session(target=Target(connection=connection))

    for prefix in PREFIXES:
        s_initialize(f"{prefix.upper()} Command")
        if s_block_start("CommandBlock"):
            s_string(prefix, name="command_prefix", fuzzable=True)
            s_delim(" ", fuzzable=False)
            # Use index for unique names (fixes duplicate-name error)
            for i, payload in enumerate(PAYLOADS):
                s_string(payload, name=f"payload_{i}", fuzzable=True)
            s_delim("\n", fuzzable=False)
            s_block_end()
        session.connect(s_get(f"{prefix.upper()} Command"))

    # Begin fuzzing
    print("[*] Starting fuzzing session")
    try:
        session.fuzz()
    finally:
        # Cleanup monitor and power as appropriate
        stop_monitor.set()
        if crash_detected.is_set():
            print("[!] Crash detected by monitor. (Pi already powered OFF.)")
        else:
            print("[*] Fuzzing complete. Powering OFF Pi.")
            relay_off(arduino, RELAY_CHANNEL)
        print("[*] Done.")

if __name__ == "__main__":
    main()
