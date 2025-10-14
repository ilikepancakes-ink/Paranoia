#!/usr/bin/env python3

import curses
import time
import subprocess
import re
import sys

def read_logo():
    try:
        with open('logo.txt', 'r') as f:
            return f.read()
    except FileNotFoundError:
        return "Logo file not found!"

def loading_phase(stdscr):
    stdscr.clear()
    logo = read_logo()
    lines = logo.split('\n')
    max_y, max_x = stdscr.getmaxyx()
    for i, line in enumerate(lines):
        if i < max_y - 3:
            stdscr.addstr(i, 0, line[:max_x-1])
    stdscr.refresh()
    time.sleep(1)
    progress_y = max_y - 3
    bar_char = '█'
    for i in range(21):  # 0 to 100% in 5% steps
        progress = i * 5
        filled = int((progress / 100) * (max_x - 10))
        bar = bar_char * filled + '-' * ((max_x - 10) - filled)
        stdscr.addstr(progress_y, 0, f"Loading: {progress:3}% [{bar}]")
        stdscr.refresh()
        time.sleep(0.1)
    stdscr.addstr(progress_y + 1, 0, "Loading complete. Scanning devices...")
    stdscr.refresh()
    time.sleep(1)

def scan_wifi():
    try:
        # Get WiFi information using human-readable format and parse it properly
        result = subprocess.run(['nmcli', '-c', 'no', 'device', 'wifi', 'list'], capture_output=True, text=True, timeout=10)
        devices = []

        lines = result.stdout.strip().split('\n')
        if len(lines) > 0:
            for line in lines[1:]:  # Skip header line
                if line.strip():
                    # Split on 2+ spaces to handle SSIDs with spaces correctly
                    parts = re.split(r'\s{2,}', line.strip())
                    if len(parts) >= 8:
                        # Parse: IN-USE BSSID SSID MODE CHAN RATE SIGNAL BARS SECURITY
                        in_use = '*' in parts[0]
                        bssid = parts[1]
                        ssid = parts[2] if parts[2] != '--' else '<Hidden>'
                        mode = parts[3]
                        channel = parts[4] if parts[4] != '--' else 'Unknown'
                        rate = parts[5]
                        signal_part = parts[6].strip('*☆')
                        security = ' '.join(parts[7:])  # Security might have spaces

                        # Determine frequency and band from channel
                        freq = 'Unknown'
                        band = 'Unknown'
                        if channel != 'Unknown':
                            try:
                                chan_num = int(channel)
                                if chan_num <= 14:
                                    freq = '2.4GHz'
                                    band = '2.4GHz'
                                elif chan_num >= 36:
                                    freq = '5GHz'
                                    band = '5GHz'
                            except ValueError:
                                pass

                        # Try to get IP address for connected network
                        ip_address = 'N/A'
                        if ssid and ssid != '<Hidden>':
                            try:
                                ip_result = subprocess.run(['nmcli', '-t', '-f', 'IP4.ADDRESS', 'connection', 'show', ssid.replace(' ', '_')],
                                                         capture_output=True, text=True, timeout=5)
                                ip_line = ip_result.stdout.strip()
                                if ip_line and '/' in ip_line:
                                    ip_address = ip_line.split('/')[0]
                            except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
                                pass

                        devices.append({
                            'type': 'wifi',
                            'ssid': ssid,
                            'bssid': bssid,
                            'mac_address': bssid,
                            'signal': signal_part,
                            'security': security.strip(),
                            'channel': channel,
                            'frequency': freq,
                            'max_rate': rate,
                            'ip_address': ip_address,
                            'band': band,
                            'in_use': '*' if in_use else '',
                            'mode': mode
                        })

        return devices
    except subprocess.TimeoutExpired:
        return [{'type': 'wifi', 'error': 'WiFi scan timed out'}]
    except FileNotFoundError:
        return [{'type': 'wifi', 'error': 'nmcli not found - WiFi scanning unavailable'}]
    except Exception as e:
        return [{'type': 'wifi', 'error': f'WiFi scan error: {str(e)}'}]

def scan_bluetooth():
    try:
        # Try using pybluez for more detailed info
        import bluetooth
        nearby_devices = bluetooth.discover_devices(duration=8, lookup_names=True, flush_cache=True, lookup_class=True)
        devices = []
        for addr, name, device_class in nearby_devices:
            # Determine device type from device_class
            device_type = 'Unknown'
            if device_class & 0x1f00:
                major_class = (device_class >> 8) & 0x1f
                if major_class == 1:
                    device_type = 'Computer'
                elif major_class == 2:
                    device_type = 'Phone'
                elif major_class == 3:
                    device_type = 'LAN/Network Access Point'
                elif major_class == 4:
                    device_type = 'Audio/Video'
                elif major_class == 5:
                    device_type = 'Peripheral'
                elif major_class == 6:
                    device_type = 'Imaging'

            # Get RSSI (signal strength) if possible
            rssi = 'Unknown'
            try:
                import bluetooth as bt
                if hasattr(bt, 'read_local_bdaddr'):
                    # This might not work, but we'll try for comprehensive info
                    pass
            except:
                pass

            devices.append({
                'type': 'bluetooth',
                'address': addr,
                'mac_address': addr,
                'name': name or 'Unknown',
                'paired': False,
                'device_class': device_type,
                'device_class_hex': f'0x{device_class:06X}',
                'rssi': rssi
            })
        return devices
    except ImportError:
        # PyBluez not available, try bluetoothctl for detailed info
        try:
            # Start scan
            subprocess.run(['bluetoothctl', 'scan', 'on'], capture_output=True, timeout=5)
            time.sleep(8)  # Wait for scanning

            # Get detailed device info
            result = subprocess.run(['bluetoothctl', 'devices'], capture_output=True, text=True, timeout=10)
            devices = []
            if 'No default controller available' not in result.stderr:
                lines = result.stdout.strip().split('\n')
                for line in lines:
                    match = re.match(r'Device\s+([0-9A-F:]{17})\s+(.+)', line)
                    if match:
                        addr, name = match.groups()

                        # Try to get additional info from info command
                        info_result = subprocess.run(['bluetoothctl', 'info', addr],
                                                   capture_output=True, text=True, timeout=5)

                        # Parse additional information
                        rssi = 'Unknown'
                        paired = 'No'
                        device_class = 'Unknown'
                        for info_line in info_result.stdout.split('\n'):
                            if 'RSSI:' in info_line:
                                rssi_match = re.search(r'RSSI:\s*(-?\d+)', info_line)
                                if rssi_match:
                                    rssi = f"{rssi_match.group(1)} dBm"
                            elif 'Paired:' in info_line:
                                paired = 'Yes' if 'yes' in info_line.lower() else 'No'
                            elif 'Class:' in info_line:
                                class_match = re.search(r'Class:\s+0x([0-9A-Fa-f]+)', info_line)
                                if class_match:
                                    device_class = f"0x{class_match.group(1).upper()}"

                        devices.append({
                            'type': 'bluetooth',
                            'address': addr,
                            'mac_address': addr,
                            'name': name,
                            'paired': paired,
                            'rssi': rssi,
                            'device_class': device_class
                        })

            subprocess.run(['bluetoothctl', 'scan', 'off'], capture_output=True, timeout=5)
            return devices if devices else [{'type': 'bluetooth', 'error': 'No Bluetooth devices found'}]
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            pass
    except Exception:
        pass

    # Fallback - basic hcitool scan
    try:
        result = subprocess.run(['hcitool', 'scan'], capture_output=True, text=True, timeout=10)
        devices = []
        lines = result.stdout.strip().split('\n')[1:]  # Skip header
        for line in lines:
            parts = line.split()
            if len(parts) >= 2:
                addr = parts[0]
                name = ' '.join(parts[1:])
                devices.append({
                    'type': 'bluetooth',
                    'address': addr,
                    'mac_address': addr,
                    'name': name,
                    'paired': 'Unknown',
                    'rssi': 'Unknown',
                    'device_class': 'Unknown'
                })
        return devices
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        pass

    return [{'type': 'bluetooth', 'error': 'No Bluetooth scanning method available'}]

def get_devices():
    wifi_devices = scan_wifi()
    bt_devices = scan_bluetooth()
    return wifi_devices + bt_devices

def display_devices(stdscr, devices):
    curses.curs_set(0)
    selected = 0
    while True:
        stdscr.clear()
        h, w = stdscr.getmaxyx()
        logo = read_logo()
        logo_lines = logo.split('\n')
        for i, line in enumerate(logo_lines[:h-10]):
            stdscr.addstr(i, 0, line[:w-1])

        stdscr.addstr(h-5, 0, "Detected Devices:")
        stdscr.addstr(h-4, 0, "Use ↑/↓ to navigate, Enter to select, q to quit")

        max_display = h - 6
        start = max(0, selected - max_display + 1)
        for i in range(max_display):
            idx = start + i
            if idx >= len(devices):
                break
            device = devices[idx]
            display_name = get_device_display_name(device)
            attr = curses.A_REVERSE if idx == selected else curses.A_NORMAL
            stdscr.addstr(4 + i, 0, f" {idx+1:2d}. {display_name}", attr)

        key = stdscr.getch()
        if key == curses.KEY_UP and selected > 0:
            selected -= 1
        elif key == curses.KEY_DOWN and selected < len(devices) - 1:
            selected += 1
        elif key in [curses.KEY_ENTER, 10, 13]:  # Different enter key codes
            show_device_info(stdscr, devices[selected])
        elif key == ord('q'):
            break
        stdscr.refresh()

def get_device_display_name(device):
    if 'error' in device:
        return f"{device['type'].upper()}: {device['error']}"
    elif device['type'] == 'wifi':
        return f"WiFi: {device['ssid']} ({device['signal']}% signal)"
    elif device['type'] == 'bluetooth':
        if 'name' in device:
            return f"BT: {device['name']} ({device['address']})"
        return f"BT: {device['address']}"
    return "Unknown Device"

def show_device_info(stdscr, device):
    h, w = stdscr.getmaxyx()
    win = curses.newwin(h-4, w-4, 2, 2)
    win.border()
    win.addstr(2, 2, f"Device Information for {get_device_display_name(device)}")

    y = 4
    if 'error' in device:
        win.addstr(y, 2, device['error'])
        y += 2
    else:
        for key, value in device.items():
            win.addstr(y, 2, f"{key.capitalize()}: {value}")
            y += 1
            if y > h - 8:
                win.addstr(y, 2, "... (truncated)")
                break

    try:
        win.addstr(y+1, 2, "Press any key to continue...")
        win.refresh()
        win.getch()
    except curses.error:
        pass  # Skip error if text doesn't fit

def main(stdscr):
    # Check for required tools - make Bluetooth optional since we have fallbacks
    missing_critical = []
    if not check_tool('nmcli'):
        missing_critical.append('nmcli (for WiFi scanning)')

    if missing_critical and not check_tool('wget'):
        stdscr.addstr(0, 0, "Critical tools missing:")
        for i, tool in enumerate(missing_critical):
            stdscr.addstr(i+1, 0, f" - {tool}")
        stdscr.addstr(i+3, 0, "Trying fallback WiFi scanning...")
        stdscr.refresh()
        time.sleep(2)

    loading_phase(stdscr)
    devices = get_devices()
    display_devices(stdscr, devices)

def check_tool(name):
    try:
        subprocess.run([name, '--help'], capture_output=True, timeout=5)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError, subprocess.TimeoutExpired):
        return False

if __name__ == "__main__":
    curses.wrapper(main)
