# CSR CA Signer

Windows GUI utility for submitting certificate signing requests to Microsoft Active Directory Certificate Services with built-in `certreq.exe` and `certutil.exe`.

## Run

Double-click `Run-CsrCaSigner.vbs` to start without a console window, or use `Run-CsrCaSigner.cmd` if you want a simple command launcher.

You can also run:

```powershell
powershell.exe -NoProfile -STA -ExecutionPolicy Bypass -File .\CsrCaSigner.ps1
```

## What It Does

- Imports CSR files accepted by Windows certificate tools, including PEM/Base64 and DER PKCS#10 requests.
- Dumps/parses the CSR with `certutil -dump` and falls back to `certreq -dump`.
- Prompts for CA config, certificate template, SAN values, and extra request attributes.
- Loads enabled templates from the selected CA with `certutil -CATemplates` and lets you choose one.
- Submits the CSR with `certreq -submit`.
- Retrieves pending requests by request ID with `certreq -retrieve`.
- Writes compatible output files:
  - binary DER certificate: `.cer`
  - PEM certificate: `.pem`
  - binary PKCS#7 chain: `.p7b`
  - PEM/Base64 chain: `.chain.pem`
  - full CA response: `.rsp`
  - tool output log: `.log.txt`
  - certificate dump: `.details.txt`
  - metadata: `.metadata.json`

## Notes

For an existing CSR, subject and public key are part of the signed request. A Microsoft CA usually cannot safely replace the subject during signing unless policy/template settings allow it. Use the template and SAN fields for normal AD CS submission attributes, and use the extra attributes box for CA-specific attributes.
