# Terminal-Bench 2.1 dataset resolution

Harbor 0.21.0 distinguishes legacy `name@version` datasets from package datasets in `org/name@ref` form. The frozen canonical package slug is `terminal-bench/terminal-bench-2-1`; omission of `@ref` resolves to `latest`. The legacy label `terminal-bench@2.1` is not equivalent and must be rejected rather than silently redirected.

Official cross-checks: the [Terminal-Bench 2.1 repository](https://github.com/harbor-framework/terminal-bench-2-1) uses `harbor run -d terminal-bench/terminal-bench-2-1`, and the [Harbor Hub dataset page](https://hub.harborframework.com/datasets/terminal-bench/terminal-bench-2-1/latest) identifies that public dataset and lists 89 tasks.

The installed 0.21.0 authority paths are `harbor/cli/download.py` (`download_command`, `_download_dataset`), `harbor/db/client.py` (`RegistryDB.get_package_type`, `resolve_dataset_version`), `harbor/registry/client/package.py` (`PackageDatasetClient`), `harbor/models/package/reference.py` (`PackageReference.parse`), and `harbor/auth/client.py` (`create_authenticated_client`). The latter explicitly uses anonymous access when no credential exists and permits public reads.

The minimal diagnostic installs exactly Harbor 0.21.0, uses anonymous public Hub access, discovers package metadata, and exports the dataset without starting a Harbor job or benchmark trial. It checks 89 namespaced task IDs against a digest derived from the preserved local task-ID set and emits a representation-aware manifest containing every file beneath the 89 materialized task directories. Content identity is decided only after that manifest is compared read-only with the preserved local tree.
