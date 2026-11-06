"""Original ZEROTH-001 client, kept for backward compatibility.

New code should use ``zeroth.generators.OllamaGenerator`` (chat API, options,
model digest). This module is intentionally unchanged in behaviour.
"""

import json
import urllib.error
import urllib.request

OLLAMA_URL = "http://localhost:11434/api/generate"
DEFAULT_MODEL = "qwen2.5:3b"


def generate_response(prompt, system_prompt=None, model=DEFAULT_MODEL):
    """Send a prompt to a locally running Ollama model."""
    payload = {"model": model, "prompt": prompt, "stream": False}
    if system_prompt:
        payload["system"] = system_prompt
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(OLLAMA_URL, data=data, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=120) as response:
            result = json.loads(response.read().decode("utf-8"))
        return result.get("response", "")
    except urllib.error.URLError as error:
        raise RuntimeError(f"Could not connect to Ollama. Is Ollama running? Details: {error}") from error


if __name__ == "__main__":
    print(generate_response(prompt="Explain prompt injection in simple terms."))
