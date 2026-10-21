import requests

OLLAMA_URL = "http://localhost:11434/api/generate"

prompt_test = """
Tu es un analyste SOC. Analyse ce log d'authentification et indique en 2 phrases si l'action est suspecte :
Log: "Failed password for invalid user admin from 192.168.1.150 port 44210 ssh2"
"""

payload = {
    "model": "mistral",
    "prompt": prompt_test,
    "stream": False
}

try:
    response = requests.post(OLLAMA_URL, json=payload)
    if response.status_code == 200:
        print("--- Réponse du LLM ---")
        print(response.json().get("response"))
    else:
        print(f"Erreur HTTP : {response.status_code}")
except Exception as e:
    print(f"Erreur de connexion à Ollama : {e}")
