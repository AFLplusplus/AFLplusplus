# AFL++ Licensing

AFL++ is licensed under the **GNU Affero General Public License, version 3 or
later (AGPL-3.0-or-later)**.

This page explains the licensing in plain language. The authoritative texts are
the license files themselves (linked below).

## TL;DR

- **Using AFL++ under the AGPL is free** and always will be. Most users need
  nothing more than this.
- The project as a whole is **AGPL-3.0-or-later**, because some AGPL-licensed
  files are part of the `afl-fuzz` fuzzer.
- **Many source files are individually available under the Apache-2.0
  License**, while others are AGPL-3.0-or-later. Each file declares its own
  license in its `SPDX-License-Identifier` header — that header is what applies,
  so check the file you use and adhere to it.
- A **commercial license** is available for organizations that cannot or do not
  want to comply with the AGPL. It is **not sold** — you obtain it by donating
  to a good cause (see below). The project or its inviduals receives no money.

## The three ways you can use AFL++

### 1. Under the AGPL-3.0-or-later (default, free)

Anyone may use, study, modify, and distribute AFL++ under the terms of the
[GNU AGPL-3.0-or-later](LICENSE). The main obligation to be aware of: if you
modify AFL++ and let others interact with your modified version over a network,
the AGPL requires you to offer them the corresponding source code. If that is
fine for you, you are done — no payment, no donation, nothing else required.

### 2. Per file under Apache-2.0 (for files marked Apache-2.0)

Many AFL++ source files carry an `SPDX-License-Identifier: Apache-2.0` marker and
remain available under the [Apache License 2.0](LICENSE.Apache-2.0); you may
reuse those individual files in your own projects under Apache-2.0. Other files
are marked `SPDX-License-Identifier: AGPL-3.0-or-later`. Always check the header
of the file you use and adhere to the license stated there.

Note: the **combined** `afl-fuzz` program links AGPL-licensed files, so any
binary or larger work that includes them is AGPL as a whole. The Apache-2.0
option applies to the Apache-2.0 files taken individually, not to the combined
AGPL work.

### 3. Under the commercial license (optional, for companies)

If your organization cannot or does not want to comply with the AGPL, you can
obtain a one-year commercial license that lets you use AFL++ without the AGPL's
obligations. See the full terms in [LICENSE.COMMERCIAL](LICENSE.COMMERCIAL).

The short version:

- **The project earns nothing.** We do not sell licenses. Instead you donate to
  a good cause, and the donation is what grants the license.
- **Donate EUR 20,000** (twenty thousand euros, €20,000), or the equivalent in
  another currency, to **either** the
  [Electronic Frontier Foundation (EFF)](https://www.eff.org/) **or** the
  [Chaos Computer Club (CCC)](https://www.ccc.de/).
- **Email proof** of the donation (recipient, amount, date, donor) to
  **afl@aflplus.plus**.
- Your commercial license is then effective **as of the donation date** and
  lasts **one year**.
- When the year ends it **fully expires** — to keep using AFL++ you must renew
  (donate again), switch to AGPL compliance, or stop using AFL++.

## Third-party components

AFL++ bundles third-party code that keeps its own separate license, including
(non-exhaustively) xxHash (BSD-2-Clause), t1ha (Zlib), libFuzzer
(Apache-2.0-with-LLVM-exception), and various git submodules. These are **not**
relicensed and are governed solely by their own license texts. Each such file
carries its own `SPDX-License-Identifier`.

## File map

| File | What it is |
|------|------------|
| [`LICENSE`](LICENSE) | Full AGPL-3.0 text — the project's overall license |
| [`LICENSE.Apache-2.0`](LICENSE.Apache-2.0) | Full Apache-2.0 text — the license of the Apache-2.0 files |
| [`LICENSE.COMMERCIAL`](LICENSE.COMMERCIAL) | The optional, donation-based commercial license |
| `SPDX-License-Identifier:` headers | Per-file license markers in the source |

Questions about licensing: **afl@aflplus.plus**
