# How Release Sentinel Protects Open-Source Software: A Plain-Language Explainer

Imagine you order a popular board game online. When the expansion pack arrives in the mail, everything looks normal on the outside—the official logo, the sealed box, the exact shrink-wrap. But hidden inside the instruction manual is a slip of paper telling you to mail your house keys to a stranger. 

That is what a **software supply chain attack** looks like in the programming world.

---

## 1. The Hidden Trap in Modern Software

Today, almost every computer program is built like a Lego set. When a developer builds a website or an app, they don't write every single piece of code from scratch. Instead, they download thousands of pre-made building blocks called **packages** or **libraries** from public registries like **npm** (the world's largest repository of JavaScript code).

Whenever an author of one of those packages releases an update (say, moving from version `1.2.0` to `1.2.1`), developers around the world download it automatically to get new features or bug fixes.

Attackers know this. If a hacker can steal a package maintainer's login password, or trick a maintainer into accepting malicious code, they can release a poisoned update. Within minutes, tens of thousands of companies and users might download that update—giving the attacker access to their servers, databases, and passwords.

---

## 2. Why Can't Normal Antivirus Stop This?

Traditional antivirus tools look for **known signatures**—like digital fingerprints of viruses that have already been caught in the wild. 

Supply-chain attacks are completely different:
1. **Brand-New Code**: Attackers write custom, one-time code for each attack. It has never been seen by any antivirus database.
2. **Sneaky Execution**: The malicious code often runs the exact second you install the package (using "install scripts"), before standard security scanners even look at it.
3. **Sandbox Evasion**: If you try to run the package in an isolated test environment (a "sandbox"), the malware can detect it, wait for 30 minutes, or stay silent unless it detects a specific production server.

---

## 3. How Release Sentinel Works

**Release Sentinel** is an automated security gate that inspects software updates *before* they are installed. Think of it as an ultra-high-speed airport baggage scanner for software packages.

Release Sentinel follows three core principles:

### A. Zero Code Execution (Look, Don't Run)
Release Sentinel **never executes** the package code. Running untrusted code to see if it's safe is dangerous. Instead, Release Sentinel analyzes the text, structure, and grammar of the files in memory without ever running them.

### B. Time-Travel Diffing (Comparing Old vs. New)
When version `2.0.1` of a package is published, Release Sentinel asks: *What actually changed since version `2.0.0`?*
Using a time-aware registry client, it travels back in time to the exact date the update was released, pulls the clean previous version, and computes a surgical diff (difference report). 

### C. Corroborated Behavioral Evidence (Not Single Clues)
Normal software often legitimately uses the internet or reads environment settings. If a scanner blocked a package just because it connected to the web, developers would turn the scanner off due to annoying false alarms.

Release Sentinel only issues a high-confidence **BLOCK** when dangerous behaviors **corroborate** each other:
- *Connecting to the internet* is normal.
- *Reading your private password file* is suspicious.
- *Reading your private password file AND immediately connecting to an external server in the exact same script* is an attack $\to$ **BLOCK**.
- *Running a background command during `npm install` AND downloading a file from an unknown IP address* $\to$ **BLOCK**.

---

## 4. The Late-2026 "Hollow Release" Mystery

In late 2026, attackers changed their tactics. They stopped putting malicious JavaScript code into their updates!

Instead, an attacker would publish a package where every single original code file was 100% identical to the clean version. But in the package's configuration file (`package.json`), they quietly added a new dependency with a lookalike name.

The payload wasn't in the package itself—it was hiding one level deeper inside that innocent-sounding dependency. Because the main package had no modified code files, older scanners saw a completely clean update and allowed it through.

We call this a **Hollow Release**.

### Version 1.2.1: Honest, Experimental Hollow Protection (`--experimental-hollow`)
In Version 1.2.1, Release Sentinel provides specialized behavioral checks to inspect hollow releases:
1. **`hollow_dependency_injection`**: Did an update modify *zero* code files, but suddenly add a direct runtime dependency? (Legitimate packages rarely add new runtime dependencies without writing any code that uses them.)
2. **`lookalike_dependency_name`**: Does the added dependency name use npm convention affixes (like `node-` or `-cli`), character swaps/homoglyphs (like `cha1k`), or typosquats of famous packages?

**Scientific Honesty & Guardrails**:
- During testing, we caught ourselves: an earlier experimental prototype included specific sample strings (like `"easy-"`). In Version 1.2.1, we strictly purged all sample-derived strings, relying only on general algorithmic rules.
- Furthermore, because zero packages in our 800-package benign benchmark were hollow releases that added dependencies, an automated BLOCK rule could not be proven safe against false alarms.
- Therefore, in **Version 1.2.1**, the default configuration matches Version 1.1's thoroughly validated policy. Hollow release detection is provided behind an **`--experimental-hollow`** flag that flags these updates for **human review (WARN)** rather than automated blocking.

---

## 5. How Do We Know It Works?

We tested Release Sentinel against two massive real-world benchmarks:
1. **1,349 Real Attack Samples**: Every single confirmed malicious npm package published between 2024 and late 2026 from the Datadog security research archive.
2. **800 Legitimate, Clean Package Updates**: Real updates from the most popular and complex libraries in the world (like `react`, `webpack`, `typescript`, and `express`).

### The Results:
- **Zero False Blocks**: Across all 800 clean package updates, Release Sentinel issued **0 false BLOCKs (0.00%)**.
- **Over 81% High-Confidence Block Rate**: Out of 1,349 real attacks, Release Sentinel blocked over 81% with zero human intervention, and flagged over 90% for human review.
- **Lightning Fast**: Inspecting a package takes less than **0.2 seconds** on average.

Release Sentinel proves that software defenses can be both iron-clad against real attackers and completely silent during daily, legitimate software development.
