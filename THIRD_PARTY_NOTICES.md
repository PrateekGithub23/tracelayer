# Third-Party Notices

TraceLayer's own code is licensed under the terms in [LICENSE](LICENSE). It uses and, in some artifacts,
redistributes the following third-party material. Licences were read from package metadata and upstream
LICENSE files on 2026-11-15.

## Data redistributed in the public demo and samples

**OTRF Security-Datasets** (https://github.com/OTRF/Security-Datasets): Windows event logs from the
"Mordor shire" lab, used in the demo snapshot and in dataset samples.

> MIT License, Copyright (c) 2021 Open Threat Research Forge.
> Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
> associated documentation files (the "Software"), to deal in the Software without restriction, including
> without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the
> following conditions: The above copyright notice and this permission notice shall be included in all
> copies or substantial portions of the Software. THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
> KIND, EXPRESS OR IMPLIED. (Full text: https://github.com/OTRF/Security-Datasets/blob/master/LICENSE)

TraceLayer adds normalised fields next to each unmodified raw record. In the public demo, credentials
inside raw records are redacted for display, and those records are flagged.

## Model output in the public demo

Some analyses in the demo were generated locally with **Llama 3.2 (3B)** via Ollama. Built with Llama.
Llama 3.2 is licensed under the Llama 3.2 Community License, Copyright © Meta Platforms, Inc.
(https://www.llama.com/llama3_2/license/). TraceLayer does not distribute the model.

## Fonts bundled in the web UI

Inter and JetBrains Mono (via `@fontsource`), SIL Open Font License 1.1 (https://openfontlicense.org).

## Software dependencies

Frontend production dependencies (npm): MIT, ISC, BSD-3-Clause and OFL-1.1 (fonts). Notable packages:
React, React Router, TanStack Query, Cytoscape.js, Recharts and lucide-react.

Backend dependencies (49 packages): MIT, BSD-2/3-Clause, Apache-2.0, MIT-0, MPL-2.0 (`certifi`,
`pathspec`; used unmodified) and **LGPL-3.0-only (`psycopg`, `psycopg-binary`)**. psycopg is used unmodified
as a separately installed library, and anyone can replace it. Its licence text ships with the package
inside the Docker image. Source: https://github.com/psycopg/psycopg.

Container base images: `python:3.12.16-slim`, `postgres:16.16-alpine`,
`nginxinc/nginx-unprivileged:1.31.7-alpine`, `node:20.20.2-alpine` (build stage only), and optionally
`ollama/ollama:0.40.16`. Each includes its own licences.

To regenerate the dependency inventory:
`cd frontend && npx license-checker --production --summary` and, for Python, read `License-Expression`
from the installed packages' metadata (as recorded in the git history of this file).
