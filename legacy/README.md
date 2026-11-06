# legacy/

Move your original ZEROTH-001..005 scripts here (`prompt_injection_test.py`,
`indirect_prompt_injection_test.py`, the old `response_guard.py`) so history is
preserved. Everything they did is reproduced by the new platform:

| Old script | New equivalent |
|---|---|
| `prompt_injection_test.py` | `zeroth run --probes direct.override --defenses none,output_guard --trials 5` (payload `o1_original` is your original attack) |
| `indirect_prompt_injection_test.py` | `zeroth run --probes indirect.document ...` (payload `i1_classic` is your original document) |
| `python -m src.zeroth.response_guard` | `python -m unittest tests.test_guard` or `zeroth guard-test "<text>"` |

`src/zeroth/ollama_client.py` is kept unchanged for compatibility.
