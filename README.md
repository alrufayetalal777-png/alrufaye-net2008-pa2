# NET2008 PA2 — Fleet Compliance Auditor
Student: [Enter your name] | ID: 101344712
Requires Python 3 and PyYAML (`python -m pip install pyyaml`).
Run: `python pa2.py DEVICES.xml POLICY.yaml`
Example: `python pa2.py PA2_sample.xml PA2_policy.yaml`
Writes `audit.json` in the current directory and prints a summary.
Devices without IDs are skipped; missing policy keys disable corresponding checks.
The tool reports unknown roles, missing owners, down-interface limits and outdated OS versions.
