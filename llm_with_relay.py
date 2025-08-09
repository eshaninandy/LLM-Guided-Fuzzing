import os
import time
import threading
import socket
import serial

from gpt4all import GPT4All
from boofuzz import (
    Session, Target, TCPSocketConnection,
    s_initialize, s_block_start, s_block_end,
    s_string, s_delim, s_get
)

#  Configuration 
TARGET_IP            = "192.168.2.2"
TARGET_PORT          = 5515
MODEL_PATH           = os.path.expanduser(
    "~/Library/Application Support/nomic.ai/GPT4All"
)
MODEL_NAME           = "Nous-Hermes-2-Mistral-7B-DPO.Q4_0.gguf"
ARDUINO_PORT         = "/dev/tty.usbmodem11101"
RELAY_CHANNEL        = 1
TCP_CHECK_INTERVAL   = 2     # seconds between TCP checks
DOWN_TIMEOUT         = 90    # seconds of continuous TCP downtime → reboot Pi
PI_BOOT_WAIT         = 30    # wait after power-on before fuzzing
PI_POWER_CYCLE_OFF   = 3     # how long to hold OFF during reboot
SERVICE_BOOT_TIMEOUT = 180   # max wait for service to reappear

PREFIXES = [
    "ping","exec","run","exit","get",
    "set","info","config","update","version",
    "halt"]

#  Load LLM 
print("[*] Loading LLM model...")
llm = GPT4All(model_name=MODEL_NAME, model_path=MODEL_PATH)

def generate_payload():
    examples = ["admin", "root", "ls", "echo test", "reb00t", "shutdown", "%x%x%x%x"]
    prompt = (
        "Generate ONE shell-style payload (no prefix) for a TCP backdoor on port 5515.\n"
        "The service understands simple commands. Known crash string: 'halt'.\n"
        f"Example payloads include: {', '.join(examples)}.\n"
        "Use obfuscation, pipes, subshells, nulls, malformed syntax.\n"
        "Return exactly the payload, no explanation."
    )
    resp = llm.generate(prompt, max_tokens=80, temp=1.2)
    return resp.splitlines()[0].strip()

#  Arduino / Relay helpers 
def open_arduino(port, baud=9600, open_wait=2.0):
    print("[*] Connecting to Arduino...")
    ser = serial.Serial(port, baud)
    time.sleep(open_wait)  # allow Arduino sketch to initialize
    print("[*] Connected to Arduino.")
    return ser

def relay_on(ser, channel):
    ser.write(f"ON{channel}\n".encode())

def relay_off(ser, channel):
    ser.write(f"OFF{channel}\n".encode())

#  TCP / Pi-reboot monitor 
stop_monitor = threading.Event()
reboot_lock  = threading.Lock()

def tcp_is_up():
    try:
        with socket.create_connection((TARGET_IP, TARGET_PORT), timeout=1.5):
            return True
    except OSError:
        return False

def power_cycle_and_wait(arduino_ser):
    print("[!] Rebooting Pi via relay…")
    relay_off(arduino_ser, RELAY_CHANNEL)
    time.sleep(PI_POWER_CYCLE_OFF)
    relay_on(arduino_ser, RELAY_CHANNEL)
    print("[*] Waiting for Pi boot…")
    time.sleep(PI_BOOT_WAIT)

    deadline = time.time() + SERVICE_BOOT_TIMEOUT
    while time.time() < deadline and not stop_monitor.is_set():
        if tcp_is_up():
            print("[*] Service back up; resuming fuzz.")
            return
        time.sleep(TCP_CHECK_INTERVAL)
    print("[!] Service did not return in time; monitor will keep watching.")

def monitor_thread_fn(arduino_ser):
    down_since = None
    print("[*] TCP monitor started.")
    while not stop_monitor.is_set():
        if tcp_is_up():
            down_since = None
        else:
            if down_since is None:
                down_since = time.time()
            elif time.time() - down_since >= DOWN_TIMEOUT:
                if reboot_lock.acquire(False):
                    try:
                        power_cycle_and_wait(arduino_ser)
                        down_since = None
                    finally:
                        reboot_lock.release()
        time.sleep(TCP_CHECK_INTERVAL)

#  Main 
def main():
    # Open Arduino (which holds Pi OFF by default)
    arduino = open_arduino(ARDUINO_PORT)
    # Turn Pi ON once
    print("[*] Powering ON Raspberry Pi…")
    relay_on(arduino, RELAY_CHANNEL)
    time.sleep(PI_BOOT_WAIT)

    # Start background monitor
    threading.Thread(
        target=monitor_thread_fn,
        args=(arduino,),
        daemon=True
    ).start()

    # Endless LLM‐driven fuzz loops
    while True:
        session = Session(target=Target(connection=TCPSocketConnection(TARGET_IP, TARGET_PORT)))
        for prefix in PREFIXES:
            payload   = generate_payload()
            case_name = f"{prefix.upper()}_{int(time.time()*1000)}"
            s_initialize(case_name)
            if s_block_start("CommandBlock"):
                s_string(prefix,      name="command_prefix", fuzzable=False)
                s_delim(" ",          fuzzable=False)
                s_string(payload,     name="payload",         fuzzable=True)
                s_delim("\n",         fuzzable=False)
                s_block_end()
            session.connect(s_get(case_name))

        print("[*] Starting fuzz session… (Ctrl+C to quit)")
        try:
            session.fuzz()
        except KeyboardInterrupt:
            # second Ctrl+C: full shutdown
            print("\n[*] Full shutdown requested; exiting.")
            break
        print("[*] Batch complete; rebuilding session…")

    # Cleanup
    stop_monitor.set()
    print("[*] Powering OFF Raspberry Pi…")
    relay_off(arduino, RELAY_CHANNEL)
    print("[*] Done.")

if __name__ == "__main__":
    main()
