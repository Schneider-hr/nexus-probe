## Deploying

This dashboard is served by `nexus-backend` itself in production, not as a
separate Render service (see `render.yaml` and `nexus_backend/api.py`'s
static mount) - one origin, one login (HTTP Basic, see
`docs/render-deploy.md`), no CORS and no secrets baked into the JS bundle.

Render's Python build image isn't guaranteed to have Node/npm, so the build
is NOT run there. Whenever you change this dashboard's source, rebuild it
locally and copy the result into the backend before committing/deploying:

```
npm run build
rm -rf ../nexus-backend/nexus_backend/static
cp -r dist ../nexus-backend/nexus_backend/static
```

# React + TypeScript + Vite

This template provides a minimal setup to get React working in Vite with HMR and some Oxlint rules.

Currently, two official plugins are available:

- [@vitejs/plugin-react](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react) uses [Oxc](https://oxc.rs)
- [@vitejs/plugin-react-swc](https://github.com/vitejs/vite-plugin-react/blob/main/packages/plugin-react-swc) uses [SWC](https://swc.rs/)

## React Compiler

The React Compiler is not enabled on this template because of its impact on dev & build performances. To add it, see [this documentation](https://react.dev/learn/react-compiler/installation).

## Expanding the Oxlint configuration

If you are developing a production application, we recommend enabling type-aware lint rules by installing `oxlint-tsgolint` and editing `.oxlintrc.json`:

```json
{
  "$schema": "./node_modules/oxlint/configuration_schema.json",
  "plugins": ["react", "typescript", "oxc"],
  "options": {
    "typeAware": true
  },
  "rules": {
    "react/rules-of-hooks": "error",
    "react/only-export-components": ["warn", { "allowConstantExport": true }]
  }
}
```

See the [Oxlint rules documentation](https://oxc.rs/docs/guide/usage/linter/rules) for the full list of rules and categories.
