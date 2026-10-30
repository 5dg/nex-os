# Experimental image base diagnostic

This opt-in hosted job is a synthetic diagnostic, not a release or production assessment. It retains scanner output and reports failures; it does not change release gates or suppress findings.

In run 41020446572 the first, PostgreSQL image scan stopped when monitored filesystem growth exceeded its 1 GiB forecast. The source of that growth and the amount needed to finish are unknown. For a fresh run, the PostgreSQL scan forecast is 2 GiB and is admitted only with at least 4 GiB free on both the output and Docker filesystems. Workspace and Guard scans retain their 1 GiB forecasts and 3 GiB admission thresholds. All scans retain the 2 GiB reserve and stop when their forecast or the reserve is exceeded; this increase does not guarantee that PostgreSQL scanning will finish.

The build client may not prove BuildKit daemon quiescence after interruption. The job halts later phases on build failure, but termination of the disposable hosted runner remains the remaining control. Post-scan database metadata is retained per role when available and is not proof of its freshness or identity during scanning. Raw artifact contents are not asserted to be secret-free.
