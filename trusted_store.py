import json
import os

FILE_PATH = "dynamic_trusted.json"


def load_dynamic_trusted():
    if not os.path.exists(FILE_PATH):
        return set()

    try:
        with open(FILE_PATH, "r", encoding="utf-8") as f:
            return set(json.load(f))
    except:
        return set()


def save_dynamic_trusted(domains):
    try:
        with open(FILE_PATH, "w", encoding="utf-8") as f:
            json.dump(list(domains), f, indent=2)
    except Exception as e:
        print("Error saving trusted domains:", e)