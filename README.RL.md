# Fuzzing with Reinforcement Learning

Build AFL++:

```bash
make RL_FUZZING=1
```

If building with the Python RL code, use:

```bash
make PY_RL_FUZZING=1
```

Then configure a Python virtualenv (note only required if using Python RL):

```bash
python 3 -m venv venv
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
