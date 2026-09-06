# Tunnel Provider Migration Notes

## Current Policy

Legacy tunnel-provider compatibility is hard-cut. The branch does not include a raw pre-branch cluster-record decoder or migration fixture.

## Supported Current Behavior

- Omitted `mothershipConnectivity` means SSH.
- SSH clusters remain the default and do not launch the tunnel provider.
- Tunnel-provider clusters use the current branch schema and persist the selected connectivity mode.
- The provider artifact source path is create input only and is not stored in the cluster record.

## Unsupported From Original Goal

- Pre-branch raw cluster registry records are not migrated.
- Mixed-version rolling activation gates are not implemented.
- Old flat tunnel JSON is not retained as a compatibility path beyond what current parser/tests cover.

## Operational Recovery

A tunnel-only cluster has no automatic SSH fallback in this branch. Recovery requires an available control path or explicit out-of-band host access.
