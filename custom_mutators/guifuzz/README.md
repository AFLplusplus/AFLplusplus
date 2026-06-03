# GUIFuzz++: Grey-box fuzzing for desktop GUI apps

Original authors [@dotto44](https://github.com/dotto44), [@trowlett0](https://github.com/Trowlett0), and [@stevenagy](https://github.com/stevenagy).

This directory contains a custom mutator `guifuzz_mutator.py` and a GUI interaction script `guifuzz_clicks.py`.

GUIFuzz++ interprets AFL++ random bytes as interactions with the target GUI application.

Refer to the project page for more information: <https://github.com/FuturesLab/GUIFuzzPlusPlus>.

**Platform:** Linux (X11 / XOrg only). GUIFuzz++ will **not** work on Wayland.

## Dependencies

Install the dependencies required by the interaction script:

```bash
sudo apt update
sudo apt install -y xdotool scrot python3-tk python3-dev
python3 -m pip install pyautogui
```

## Environment variables

Set these environment variables before starting:

```bash
export AFL_PYTHON_MODULE=guifuzz_mutator
export PYTHONPATH=/path/to/AFLplusplus/custom_mutators/guifuzz/  # Change to your AFLplusplus path
export AFL_CUSTOM_MUTATOR_ONLY=true
export AFL_NOFORKSRV=1          # Optional: improves stability for some setups
export QT_ACCESSIBILITY=1       # Helps AT-SPI work on Qt applications
```

## Run

You will need to compile the target GUI application using AFL++'s `CC`/`CXX` wrappers. See [docs/fuzzing_in_depth.md](../../docs/fuzzing_in_depth.md) or [GUIFuzzPlusPlus#building-targets](https://github.com/FuturesLab/GUIFuzzPlusPlus?tab=readme-ov-file#building-targets).

**WARNING:** This uses PyAutoGUI and will take control of your mouse and keyboard!

Although GUIFuzz++ includes checks to avoid creating/saving/deleting files, it is still a prototype. **Use a VM or an environment without important data.**

```bash
# Make sure you are using X11. GUIFuzz++ will NOT work on Wayland.
echo "$XDG_SESSION_TYPE"

# Populate your in/ directory with random seeds.
# GUIFuzz++ uses a 3-byte interpreter structure, so use seeds whose size is divisible by 3.
head -c 300 /dev/urandom > in/seed

# Run afl-fuzz with the -K option (provide the path to the launch script)
# Move the mouse to a screen corner to stop interaction.
afl-fuzz -K ~/AFLplusplus/custom_mutators/guifuzz/guifuzz_run.sh -t 100000 -i in -o out -- /path/to/app

# Adjust -t as needed. Fuzzing GUIs is VERY SLOW; 100 seconds is a reasonable starting timeout.
```

## Additional settings

```bash
# If the framework does not support AT-SPI, disable it and close windows
# without relying on PIDs (useful when windows are not associated with PIDs).
export GUI_FUZZ_SIMPLE=1

# Time (seconds) to wait for a window with the GUI PID to appear before timing out.
export GUI_FUZZ_WINDOW_WAIT_TIMEOUT=10

# Logging mode:
# 0 = no logging
# 1 = log to file
# 2 = log to stdout
export GUI_FUZZ_LOGGING=0
```