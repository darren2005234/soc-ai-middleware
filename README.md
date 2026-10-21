# SOC AI Middleware

Middleware de triage d'alertes pour un SOC souverain. Il intercepte les alertes d'un SIEM Wazuh, les enrichit via une plateforme de Threat Intelligence (MISP), les qualifie avec un LLM local (Ollama), puis décide d'une action par un gating déterministe. Aucune donnée ne sort du réseau : l'inférence est 100 % locale.

Projet de fin d'études (Bac+5), spécialité Sécurité et Qualité des Réseaux.

## Principe

Le constat de départ : dans un SOC, les analystes de niveau 1 sont saturés d'alertes (alert fatigue). L'IA peut aider à qualifier, mais la confidentialité et la réglementation (RGPD, NIS2) interdisent d'envoyer des logs vers un LLM cloud externe. D'où un middleware souverain, hébergé on-premise.

Le point de conception central : **le LLM n'est pas décisionnaire**. Il enrichit et résume, mais la décision d'action repose sur des signaux vérifiables (niveau de règle Wazuh, correspondance MISP). Cette séparation rend le système robuste à deux limites connues des LLM :

- **L'injection de prompt** : un attaquant qui contrôle un champ de log pourrait manipuler le verdict du LLM. Comme la décision ne dépend pas du LLM, l'action reste correcte.
- **L'hallucination** : un petit modèle se trompe parfois sur une vraie menace. Le gating déterministe rattrape l'erreur.

## Architecture

```
Agent Wazuh (endpoint)
      | logs
Wazuh Manager (détection, corrélation)
      | webhook HTTP
Middleware (FastAPI)  --->  MISP (réputation IoC)
      |                --->  Ollama (qualification LLM, local)
      | gating déterministe
Remédiation : blocage IP (pfSense), isolation hôte (Wazuh Active Response)
```

## Le gating déterministe

La décision d'action est calculée à partir des seuls signaux vérifiables, jamais du verdict LLM :

| Condition | Priorité | Action |
| --- | --- | --- |
| MISP positif ET niveau >= 10 | critical | blocage IP |
| un seul signal fort (MISP ou niveau >= 10) | high | revue analyste |
| niveau 7 à 9 | medium | surveillance |
| sinon | low | aucune action |

Par défaut, le middleware tourne en dry-run : il journalise l'action qu'il aurait prise sans l'exécuter.

## Composants

| Fichier | Rôle |
| --- | --- |
| `app.py` | Middleware FastAPI : webhook, extraction du log, client MISP, appel Ollama, gating, journalisation |
| `ioc.json` | Liste d'IoC statique locale (repli quand MISP est indisponible) |
| `alerts.json` | Jeu d'alertes étiquetées pour le banc de test |
| `run_bench.py` | Rejoue le banc et compare verdict LLM et décision de gating |

## Configuration

Toute la configuration passe par variables d'environnement. Aucun secret n'est stocké dans le code.

| Variable | Défaut | Usage |
| --- | --- | --- |
| `OLLAMA_URL` | `http://localhost:11434` | API Ollama locale |
| `OLLAMA_MODEL` | `qwen2.5:3b` | Modèle de qualification |
| `MISP_URL` | `https://192.168.1.107` | Instance MISP |
| `MISP_KEY` | (vide) | Clé API MISP |
| `DRY_RUN` | `true` | Si false, les remédiations sont exécutées |
| `GATING_LEVEL_HIGH` | `10` | Seuil de niveau pour un signal fort |
| `DECISION_LOG` | `decisions.jsonl` | Journal des décisions |

## Lancement

```bash
python3 -m venv venv && source venv/bin/activate
pip install fastapi uvicorn httpx pydantic
export MISP_KEY="votre_cle"
uvicorn app:app --host 0.0.0.0 --port 8000
```

Test rapide :

```bash
curl -s localhost:8000/webhook -X POST -H "Content-Type: application/json" -d '{
  "rule": {"description": "Connexion vers IP suspecte", "level": 10},
  "agent": {"name": "PC-TEST"},
  "data": {"srcip": "198.51.100.66"}
}'
```

## Stack

Wazuh, MISP, Ollama, Python (FastAPI, pydantic, httpx), pfSense.

## Avertissement

Projet de laboratoire. Les outils et scénarios d'attaque associés ne doivent être utilisés que sur une infrastructure dont on est propriétaire.
