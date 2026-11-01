"""Interactive training shell for simulated cognitive responses; no agent execution."""
import argparse
import json
from brain_core.trainer import train, status

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mock", action="store_true",
                        help="Offline demonstration; does not call a language model")
    args = parser.parse_args()
    print("SOVEREIGN BRAIN | standalone training | simulated emotions")
    while True:
        print("\n[1] Train   [2] State and rules   [3] Exit")
        action = input("Select: ").strip()
        if action == "3":
            break
        if action == "2":
            state, history = status()
            print(json.dumps({"state": state, "recent_rules": history["rules"][-15:]},
                             indent=2, ensure_ascii=False))
        elif action == "1":
            scenario = input("Scenario: ").strip()
            feedback = input("Expected response / feedback: ").strip()
            try:
                state, result = train(scenario, feedback, mock=args.mock)
                print(json.dumps({"simulation": result, "updated_state": state},
                                 indent=2, ensure_ascii=False))
            except Exception as error:
                print(f"Training failed (no agent tasks launched): {error}")
        else:
            print("Unknown option")

if __name__ == "__main__":
    main()
