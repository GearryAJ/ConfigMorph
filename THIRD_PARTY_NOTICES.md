# Third-Party Notices

Convert-In is Apache-2.0 licensed. Dependencies retain their own licenses.

## Vendored browser assets

### Cytoscape.js 3.33.1

Copyright © 2016–2025 The Cytoscape Consortium. Licensed under the MIT License. The bundle and complete license are retained in `app/static/vendor/cytoscape/`.

### Local form adapter

`app/static/vendor/htmx/htmx.min.js` is project code: a minimal local HTMX-compatible adapter, not the upstream htmx distribution. It is covered by this project's Apache-2.0 license.

`app/static/vendor/monaco/README.txt` is only a deferral notice; no Monaco code is vendored.

## Python runtime dependencies

Significant runtime dependencies include FastAPI, Uvicorn, Jinja2, python-multipart, Pydantic Settings, SQLAlchemy, Alembic, defusedxml, and NetworkX. Their distributions and license metadata govern those components. Review dependency licenses and resolved versions before each release.