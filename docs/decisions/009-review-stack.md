# ADR 009: Dependency-light local review stack

- **Status:** Accepted for the local review application; revisit before deployment.
- **Context:** The WSGI API and SQLite persistence were already implemented and covered by focused tests. The static UI no longer met the review interface needs, and the environment later had Node/npm and a package registry available.
- **Decision:** Retain the Python standard-library WSGI API and SQLite, and replace the dashboard with React + TypeScript + Vite. Bind API and frontend to loopback, allow one configured loopback CORS origin, validate JSON transport data, and expose no live/mitigation operation through the demo API. Use `/api/v1` for the main application contract.
- **Alternatives:** Replacing the API with FastAPI/SQLAlchemy would require migrating a working tested backend without a demonstrated requirement. Keeping static HTML would duplicate application UI responsibilities; a mock-only dashboard would fail to demonstrate persistence and data integration.
- **Consequences:** The review application requires Python plus Node/npm setup and still has no OpenAPI or general authentication. HTTP integration, production build and typed-client tests pass; browser presentation is not automated because no browser instance was available. This is a local research appliance decision, not a deployment architecture.
