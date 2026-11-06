# Comparing ZEROTH with garak

Running NVIDIA's garak on the same local models gives an independent baseline and a good
portfolio section ("where does a canary-centred, defense-aware tool add value?").

garak has an Ollama generator and prompt-injection probe families. Check the exact names for your
installed version, since they change between releases:

```bash
pip install garak
python -m garak --list_probes | grep -i -E "promptinject|latentinjection|leakreplay|encoding"
python -m garak --list_generators | grep -i ollama
python -m garak --model_type ollama --model_name qwen2.5:3b --probes promptinject
```

Suggested comparison table: probes run, attack success rate, runtime, what each tool can say about
*defenses* (garak: detects vulnerabilities; ZEROTH: also quantifies mitigation and false-block cost).
