# Runtime candidate diagnostic

This is an opt-in, synthetic-only experiment, not release qualification. The
workflow builds Guard with dynamically linked musl and builds the workspace on
Alpine with its target-native dependencies. It requires trusted `main`, binds
both images to the exact event SHA, checks linux/amd64 and runs the existing
bounded smoke check and an unchanged all-severity image scan. The workflow uses
the existing diagnostic resource reserves, output limits and cleanup behavior;
failures or resource exhaustion remain failures. Raw scan output may contain
package details and is not asserted secret-free.

The candidate Node 24.22.2 differs from the application's pinned 24.19.0 engine.
The diagnostic retains npm and its dependencies in the final image: known npm
findings therefore remain visible, and the scan may correctly fail. Building,
starting or scanning these candidate images does not establish package closure,
TLS/OIDC, database, browser acceptance, reproducibility or production readiness.
No production Dockerfiles or release gates are changed.

Dispatch `Nonrelease runtime candidate diagnostic` on the reviewed `main` SHA.
Each role runs on a separate ephemeral runner and retains its image identity,
source revision, bounded logs, scanner output and available database metadata.
