# CVE-2019-13272 — Test & Exploit (Educational Only)

**Vulnerability:** Linux kernel ptrace_link credential mishandling (kernel < 5.1.17)

**USE ONLY:** In your own VM/lab with a vulnerable kernel. Do not run on systems you do not own or lack permission to test.

**Build:**  
`gcc -o test_vuln test_vuln.c`  
`gcc -o exploit exploit.c`

**Vulnerable kernel range:** Before 5.1.17 (check with `uname -r`).
