# Fuzzing with Reinforcement Learning

If building with the C++ RL code, install Boost:

```bash
sudo apt install -y libboost-all-dev
```

Build AFL++:

```bash
make RL_FUZZING=1
```

If building with the Python RL code, use:

```bash
make PY_RL_FUZZING=1
```

Then configure a Python virtualenv (only required if using Python RL):

```bash
python3 -m venv venv
source venv/bin/activate
pip3 install --upgrade pip
pip3 install -r RL-requirements.txt
```

Start the Python service:

```bash
./src/RLFuzzing.py
```

Start the fuzzer:

```bash
# TODO
```
