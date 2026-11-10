STEP 2 DATA-ACCESS ADDITION

New files:
  data_access.py
  demo_data_access.py
  tests/test_data_access.py
  docs/data_access_threat_model.md

No existing baseline file is modified. The payment demo and its original tests remain unchanged.

Run from the project root:
  .\.venv\Scripts\python.exe .\demo_data_access.py
  .\.venv\Scripts\python.exe -m unittest discover -s tests -v

Expected test count after adding the new test module: 48 total (27 original + 21 new).

The data-access demo uses synthetic in-memory fixtures only. It does not connect to a database or any external service. The current authorization remains Ed25519-signed, not zero knowledge.
