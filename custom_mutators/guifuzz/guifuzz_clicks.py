"""
Script to interact with the GUIs.

Options:
    -o specifies where afl++ is writing its input bytes. This is provided by the custom AFL++ implementation. 
    -p specifies the pid of the GUI program. Sometimes passed by AFL++.
    -d runs in direct mode. This is used to directly run a test case on a specific application. Requires [app, seed] params.

Envvars:
    -GUI_FUZZ_SIMPLE=1 - Disable AT-SPI if the framework does not support it, 
                         and close windows without using PIDs since the windows are not associated with PIDs. 
    -GUI_FUZZ_WINDOW_WAIT_TIMEOUT=10 - The time to wait for a window with the GUI pid to launch before timing out
    -GUI_FUZZ_DISABLE_ATSPI - Replaces all ATSPI operations with random clicks
    -GUI_FUZZ_LOGGING=0 - Sets how to log. 0 = No logging. 1 = Log to file. 2 = Log to stdout. 
    -GUI_FUZZ_NO_CLOSE=0 - If enabled, doesn't attempt to close windows. Sometimes useful in direct mode for triaging.
"""

import datetime
import pyautogui
import time
import signal
import os
from multiprocessing import Process
import math
import subprocess
import re
import argparse
import gi
gi.require_version('Atspi', '2.0')
from gi.repository import Atspi

import subprocess

gdb_proc = None

def start_program(program):
    def task():
        os.system(program)

    process = Process(target=task)
    process.start()

def start_program_in_gdb(program_path, log_path):
    # Create the GDB command script that runs the program and prints a backtrace on crash
    global gdb_proc
    gdb_commands = f"""
set pagination off
set logging file {log_path}
set logging on
run
bt
quit
"""
    with open("gdb_script.txt", "w") as f:
        f.write(gdb_commands)

    # Launch the program in GDB using the script
    gdb_proc = subprocess.Popen(["gdb", "--batch", "-x", "gdb_script.txt", program_path])


def get_active_window_pid():
    try:
        window_id = subprocess.check_output(["xdotool", "getactivewindow"]).decode().strip()
        xprop_output = subprocess.check_output(["xprop", "-id", window_id]).decode()
        pid_line = [line for line in xprop_output.splitlines() if "PID" in line]
        if pid_line:
            pid = pid_line[0].split()[-1]
            return int(pid)
    except (subprocess.CalledProcessError, ValueError, IndexError) as e:
        log("DEBUG", f"get_active_window_pid() failed: {e}")
    return -1

seed_path = './out/default/.cur_input'
start_window = ""
gui_pid = 0

# Parse the command line arguments
parser = argparse.ArgumentParser(description="GUI Options")
parser.add_argument("-o", "--outfile", help="The location where afl++ is writing output", required=False)
parser.add_argument("-p", "--pid", nargs=1, help="The pid of the gui program, provided by afl++", required=False)
parser.add_argument("-d", "--direct", nargs=2, help="Directly run on [app, seed]")

# Parse envvars
SIMPLE_MODE = os.getenv("GUI_FUZZ_SIMPLE") == "1"
WINDOW_WAIT_TIMEOUT = float(os.getenv("GUI_FUZZ_WINDOW_WAIT_TIMEOUT", "10"))
DISABLE_ATSPI = os.getenv("GUI_FUZZ_DISABLE_ATSPI") == "1"
NO_FORK = os.getenv("AFL_NO_FORKSRV") == "1"
LOGGING = int(os.getenv("GUI_FUZZ_LOGGING", "0"))
DELAY = int(os.getenv("GUI_FUZZ_DELAY", "0"))
NO_CLOSE = os.getenv("GUI_FUZZ_NO_CLOSE", "0") == "1"

def log(message_type, message):
    """
    Logs debug messages in a standard format.
    """
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = f"[{timestamp}] [{message_type}] {message}\n"
    
    if LOGGING == 1:
        with open('./logfile.txt', 'a') as log_file:
            log_file.write(log_entry)
    elif LOGGING == 2:
        print(log_entry)

if NO_FORK:
    time.sleep(0.5)

args = parser.parse_args()
if args.outfile:
    seed_path = args.outfile if args.outfile.startswith("/") else "./" + args.outfile
    log("DEBUG", "Setting outfile location to: " + seed_path)

if args.pid:
    gui_pid = args.pid[0]
    log("DEBUG", f"Setting GUI pid to: {int(args.pid[0])}")

try:
    log("INFO", "GUI Script Launched")
    if args.direct:  
        target_program = args.direct[0]
        seed_path = args.direct[1]

        # start_program(target_program)
        start_program_in_gdb(target_program, seed_path + "_log.txt")
        
        time.sleep(2)

        main_window_id = subprocess.check_output(['xdotool', 'getactivewindow']).strip().decode('utf-8')
        gui_pid = subprocess.check_output(['xdotool', 'getwindowpid', main_window_id]).strip().decode('utf-8')
        
    if DELAY != 0:
        time.sleep(DELAY)

    def getWindowCoords():
        """
            Returns the coordinates of the current window to interact with

            If the active window PID does not match the GUI PID, it closes the window
        """
        global start_window
        global gui_pid
        window_list = []  # start x, start y, width, height
        try:
            window_command = "xwininfo -id $(xdotool getactivewindow)"
            window_info = subprocess.check_output(window_command, shell=True, stderr=subprocess.STDOUT)

            window_info = window_info.decode('utf-8')
            info = window_info.split("\n")

            if start_window == "":
                start_window = re.search(r'Window id: (\S+)', info[1]).group(1)
                log("INFO", f"Set the starting window: {start_window}")
        
        except:
            log("INFO", "No window found to return coordinates")
            return [0, 0, 0, 0]

        try:
            window_id = subprocess.check_output(['xdotool', 'getactivewindow']).strip().decode('utf-8')
            pid = subprocess.check_output(['xdotool', 'getwindowpid', window_id]).strip().decode('utf-8')

            if gui_pid == 0:
                gui_pid = pid
                log("DEBUG", "Setting GUI pid: " + str(pid))
            elif gui_pid != pid:
                application_name = get_application_name(pid)

                # Hardcoded saves -- this shouldn't be needed, but in case!
                if application_name == "simplescreenrec" or application_name == "gnome-terminal-":
                    log("EMERGENCY", "TRIED TO CLOSE A CORE WINDOW")
                    cleanup()
                    exit(0)

                if application_name != "soffice.bin":
                    os.kill(int(pid), signal.SIGKILL)
                    log("INFO", "Killing non-gui PID: " + str(pid) + ", application: " + str(application_name))

        except subprocess.CalledProcessError as e:
            log("DEBUG", "Failed to get PID info, so returning coordinates")

        for res in info:
            temp = res.split(":")
            if (len(temp) > 1):
                match temp[0].strip():
                    case "Absolute upper-left X":
                        window_list.append(int(temp[1].strip()))
                    case "Absolute upper-left Y":
                        window_list.append(int(temp[1].strip()))
                    case "Width":
                        window_list.append(int(temp[1].strip()))
                    case "Height":
                        window_list.append(int(temp[1].strip()))
        
        log("DEBUG", "Returning coords: " + str(window_list))
        return window_list

    def is_process_alive(pid):
        return os.path.exists(f"/proc/{pid}")

    def get_active_window_name():
        try:
            # Get the active window ID
            window_id = subprocess.check_output(["xdotool", "getactivewindow"]).decode().strip()
            
            # Get the window name using xprop
            xprop_output = subprocess.check_output(["xprop", "-id", window_id, "WM_NAME"]).decode()
            
            # Extract the window name
            name_line = [line for line in xprop_output.splitlines() if "WM_NAME" in line]
            if name_line:
                window_name = name_line[0].split(" = ", 1)[-1].strip().strip('"')
                return window_name
            else:
                raise Exception("Failed to get the window name for the active window.")
        except:
            return ""


    def manual_kill():
        pyautogui.hotkey('alt', 'f4')
        pyautogui.keyDown('ctrlleft')
        pyautogui.press('q')
        pyautogui.keyUp('ctrlleft')
    
    def get_window_ids():
        try:
            output = subprocess.check_output(["xdotool", "search", "--onlyvisible", "--all", ""])
            return set(output.decode().split())
        except subprocess.CalledProcessError:
            # No windows found
            log("DEBUG", "Failed to retrieve windows")
            return set()
        finally:
            pass

    def get_window_pid(window_id):
        try:
            output = subprocess.check_output(["xprop", "-id", window_id]).decode()
            for line in output.splitlines():
                if "_NET_WM_PID(CARDINAL)" in line:
                    return int(line.split()[-1])
        except subprocess.CalledProcessError:
            return None
        finally:
            pass

    def gracefully_kill_application(pid):
        try:
            application_name = get_application_name(pid)
            if application_name == "simplescreenrec" or application_name == "gnome-terminal-":
                    log("EMERGENCY", "TRIED TO CLOSE AN UNRELATED WINDOW")
                    return
            
            os.kill(pid, signal.SIGINT)

            if is_process_alive(pid):
                os.kill(pid, signal.SIGTERM)
            log("INFO", f"Sent SIGINT to process with PID {pid}.")
        except ProcessLookupError:
            log("ERROR", f"Process with PID {pid} is already terminated.")
        except PermissionError:
            log("ERROR", f"No permission to kill process with PID {pid}.")
        except Exception as e:
            log("ERROR", f"Error sending SIGINT to PID {pid}: {e}")


    def gracefully_kill_active_application():
        try:
            pid = get_active_window_pid()
            gracefully_kill_application(pid)
        except Exception as e:
            log("ERROR", f"Error: {e}")
            manual_kill()

    # Store the initial state of windows
    initial_windows = set()
    while not initial_windows:
        initial_windows = get_window_ids()
        if not initial_windows:
            log("DEBUG", "Refetching initial windows...")
            time.sleep(0.5)

    def get_windows_by_pid(pid):
        try:
            application_name = get_application_name(pid)
            result = subprocess.run(
                ["xdotool", "search", "--pid", str(pid)],
                capture_output=True,
                text=True
            )
            window_ids = result.stdout.strip().split("\n")
            return [win_id for win_id in window_ids if win_id]
        except Exception as e:
            log("ERROR", f"Error finding windows for PID {pid}: {e}")
            return []
        finally:
            pass

    def wait_for_window_ready(pid, timeout=WINDOW_WAIT_TIMEOUT):
        start_time = time.time()
        while time.time() - start_time < timeout:
            windows = get_windows_by_pid(pid)
            if windows:
                for window_id in windows:
                    try:
                        subprocess.run(["xdotool", "getwindowgeometry", window_id],
                                    capture_output=True, text=True, check=True)
                        log("DEBUG", f"Active window pid {get_active_window_pid()}, application: {get_application_name(get_active_window_pid())} vs gui pid {pid}")
                        if get_active_window_pid() == int(pid):
                            log("DEBUG", f"Window {window_id} is ready.")
                            return window_id
                    except subprocess.CalledProcessError:
                        pass
            time.sleep(0.1)
        raise TimeoutError(f"No interactable window found for PID {pid} within {timeout} seconds.")

    def get_application_name(pid):
        try:
            with open(f"/proc/{pid}/comm", "r") as file:
                return file.read().strip()
        except FileNotFoundError:
            return "Unknown Application"

    def is_window_minimized(window_id):
        try:
            output = subprocess.check_output(["xdotool", "getwindowgeometry", window_id])
            geometry_info = output.decode()
            
            # If the window is minimized, xdotool typically reports that it's not mapped
            if "Window is not on the current desktop" in geometry_info or "unmapped" in geometry_info:
                return True
            return False
        except subprocess.CalledProcessError:
            # If xdotool fails to get window geometry, assume it's minimized (fail-safe)
            return True
        finally:
            pass

    def cleanup():

        global gdb_proc
        if gdb_proc is not None and gdb_proc.poll() is None:
            #print("Cleaning up running process...")
            gdb_proc.terminate()
            try:
                gdb_proc.wait(timeout=WINDOW_WAIT_TIMEOUT)
            except subprocess.TimeoutExpired:
                #print("Force killing...")
                gdb_proc.kill()
            exit(0)

        if NO_CLOSE:
            exit(0)
        current_windows = get_window_ids()
        new_windows = current_windows - initial_windows
        log("CLEANUP", f"Cleaning up windows")
        log("CLEANUP", f"Initial windows {initial_windows}")
        log("CLEANUP", f"Detected new windows {new_windows}")
        if not new_windows or SIMPLE_MODE:
            log("CLEANUP", f"No new windows detected, killing top application")
            gracefully_kill_active_application()
            return

        for window_id in new_windows:
            pid = get_window_pid(window_id)
            if pid:
                if is_window_minimized(window_id):
                    log("CLEANUP", f"Window ID: {window_id} is minimized. Skipping...")
                    continue

                application_name = get_application_name(pid)
                log("CLEANUP", f"PLANNING TO KILL: Window ID: {window_id}, Application Name: {application_name}, PID: {pid}")
                
                if application_name == "mutter-x11-fram":
                    continue

                # Hardcoded saves -- this shouldn't be needed, but in case!
                if application_name == "simplescreenrec" or application_name == "gnome-terminal-":
                    log("EMERGENCY", "TRIED TO CLOSE AN UNRELATED WINDOW")
                    continue

                # Gracefully kill the application
                gracefully_kill_application(pid)

        # new_windows = current_windows - initial_windows
        # if new_windows:
            # manual_kill()


    def update_window_coords():
        window_coords = getWindowCoords()
        return window_coords[0], window_coords[1], window_coords[2], window_coords[3]


    def execute_click(i, data):
        start_x, start_y, window_width, window_height = update_window_coords()

        val = ord(data[i + 1]) / 255.0
        val2 = ord(data[i + 2]) / 255.0

        x_val = start_x + window_width * val
        if x_val <= start_x:
            x_val = start_x + 1

        y_val = (start_y + y_padding) + (window_height - y_padding) * val2
        if y_val <= start_y + y_padding:
            y_val = start_y + y_padding + 1

        if window_width != 0:
            pyautogui.click(math.floor(x_val), math.floor(y_val))


    def execute_key(i, data):
        ascii_char = chr(ord(data[i + 1]))
        pyautogui.write(ascii_char)

    def get_active_window_for_app(app):
        """Finds and returns the active window/dialog for a given Atspi.Application."""
        if not app:
            return None  # No application provided

        for i in range(app.get_child_count()):
            window = app.get_child_at_index(i)
            if not window:
                continue

            role = window.get_role_name()

            # Check if it's a window or dialog AND if it's active
            if role in ["frame", "dialog"] and window.get_state_set().contains(Atspi.StateType.ACTIVE):
                return window  # Return the active window/dialog

        return None

    def find_all_interactable_elements(element, found_elements, interactable_roles):
        """ Recursively collect all interactable and visible elements in the application """
        if element is None or element.get_role_name() is None:
            return

        role_name = element.get_role_name().lower()
        state_set = element.get_state_set()  # Corrected method

        # Ensure element is both interactable and visible
        if state_set.contains(Atspi.StateType.VISIBLE) and role_name in interactable_roles:
            found_elements.append(element)

        for k in range(element.get_child_count()):
            find_all_interactable_elements(element.get_child_at_index(k), found_elements, interactable_roles)

    def get_all_atspi_elements(types):
        "Get all atspi elements of a certain type"
        # This is slow, disable AT-SPI for more speed, but less precision.
        all_elements = []
        frame_element = get_active_window_for_app(app)
        find_all_interactable_elements(frame_element, all_elements, types)

        return all_elements
    
    def execute_atspi_click(i, data, types):
        """
        Click a random atspi element of a certain type
        """
        if DISABLE_ATSPI:
            execute_click(i, data)
            return

        elements = get_all_atspi_elements(types)

        if len(elements) == 0:
            execute_click(i, data)
            return

        element = elements[i % len(elements)]
        element_name = element.get_name()

        if "open" in element_name.lower() or "save" in element_name.lower() or "paste" in element_name.lower():
            execute_click(i, data)
            return

        role = element.get_role_name()
        rect = element.get_extents(Atspi.CoordType.SCREEN)

        x, y, width, height = rect.x, rect.y, rect.width, rect.height
        window_x, window_y, window_width, window_height = getWindowCoords()

        click_x = x + width // 2
        click_y = y + height // 2

        # If the click is invalid, just do a random click rather than sit idle
        if not (window_x <= click_x <= window_x + window_width and
                window_y <= click_y <= window_y + window_height):
            execute_click(i, data)
            return

        if width > 0 and height > 0:
            pyautogui.click(click_x, click_y)

    def execute_lower():
        """
        Closes the current window, as long as it is not the starting window
        """
        if start_window == "":
            return
        
        try:
            window_command = "xwininfo -id $(xdotool getactivewindow)"
            window_info = subprocess.check_output(window_command, shell=True, stderr=subprocess.STDOUT)

            window_info = window_info.decode('utf-8')
            info = window_info.split("\n")

            if re.search(r'Window id: (\S+)', info[1]).group(1) == start_window:
                log("DEBUG", "Cannot close the starting window")
                return

            pyautogui.hotkey('alt', 'f4')

        except subprocess.CalledProcessError as e:
            return [0, 0, 0, 0]


    def choose_operation(byte_value):
        if ord(byte_value) == 2:
            return 'lower'
        elif ord(byte_value) == 3:
            return 'key'
        elif ord(byte_value) == 4:
            return 'entry'
        elif ord(byte_value) == 5:
            return 'push button'
        elif ord(byte_value) == 6:
            return 'toggle button'
        elif ord(byte_value) == 7:
            return 'check box'
        elif ord(byte_value) == 8:
            return 'radio button'
        elif ord(byte_value) == 9:
            return 'combo box'
        elif ord(byte_value) == 10:
            return 'menu item'
        elif ord(byte_value) == 14:
            return 'table cell'
        else:
            return 'click'

    def run_trial(data):
        """
        Using the provided input, run a full fuzzing trial on the application
        """

        i = 0
        # Interpret each 3 bytes of data as a click,
        # where byte 1 is a percent of the window width and byte 2 is a percent of the window height
        while i < len(data):
            if i >= len(data) - 3:
                break
            
            if gui_pid != 0 and not is_process_alive(gui_pid):
                log("ERROR", "The GUI got killed somehow")
                exit(0)

            if not SIMPLE_MODE and get_active_window_pid() != int(gui_pid):
                log("DEBUG", "Killing intruder window")
                execute_lower()

            if not SIMPLE_MODE:
                active_wdw_name = get_active_window_name().lower()
                if  not SIMPLE_MODE and ("open" in active_wdw_name or "save" in active_wdw_name or "paste" in active_wdw_name):
                    log("DEBUG", "Killing file menu window")
                    execute_lower()

            operation = choose_operation(data[i])
            # time.sleep(0.2)

            if operation == 'click':
                log("DEBUG", "Click")
                execute_click(i, data)
            elif operation == 'key':
                log("DEBUG", "Key press")
                execute_key(i, data)
            elif operation == 'lower':
                log("DEBUG", "Close window")
                execute_lower()
            elif operation == 'push button' and not SIMPLE_MODE:
                log("DEBUG", "At-spi push button")
                execute_atspi_click(i, data, {"push button"})
            elif operation == 'toggle button' and not SIMPLE_MODE:
                log("DEBUG", "At-spi toggle button")
                execute_atspi_click(i, data, {"toggle button"})
            elif operation == 'check box' and not SIMPLE_MODE:
                log("DEBUG", "At-spi check box")
                execute_atspi_click(i, data, {"check box"})
            elif operation == 'radio button' and not SIMPLE_MODE:
                log("DEBUG", "At-spi radio button")
                execute_atspi_click(i, data, {"radio button"})
            elif operation == 'combo box' and not SIMPLE_MODE:
                log("DEBUG", "At-spi combo box")
                execute_atspi_click(i, data, {"combo box"})
            elif operation == 'menu item' and not SIMPLE_MODE:
                log("DEBUG", "At-spi menu item")
                execute_atspi_click(i, data, {"menu item"})
            elif operation == 'table cell' and not SIMPLE_MODE:
                log("DEBUG", "At-spi table cell")
                execute_atspi_click(i, data, {"table cell"})
            i += 3

    if gui_pid != 0:
        try:
            window_id = wait_for_window_ready(gui_pid)
            log("DEBUG", f"Window {window_id} is ready for interaction.")
        except TimeoutError as e:
            log("ERROR", str(e))

        log("INFO", "GUI seems ready, proceeding")
    else:
        log("INFO", "Manually waiting for gui since no PID provided")
        time.sleep(5)

    y_padding = 10
    data = ""

    # Initialize AT-SPI
    if not SIMPLE_MODE:
        desktop = Atspi.get_desktop(0)
        for i in range(desktop.get_child_count()):
            if desktop.get_child_at_index(i).get_process_id() == int(gui_pid):
                app = desktop.get_child_at_index(i)
                app_name = app.get_name()

    
    # Parse the seed from the provided directory
    try:
        with open(seed_path, 'r', encoding='iso-8859-1') as f:
            data = f.read()
            log("DEBUG", f"Running with seed: {data}")
    except Exception as e:
            log("INFO", f"Error reading {seed_path}: {e}")

    run_trial(data)

    log("INFO", "Finished executing script, closing windows")
except Exception as e:
    raise
    log("ERROR", f"Terminal exception {e}, closing windows")

cleanup()
