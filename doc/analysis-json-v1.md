# PyHeap analysis JSON protocol v1

PyHeap exposes a versioned JSON document for tools that need heap facts without
parsing terminal tables or depending on the browser UI. The protocol contains only
facts derived from a PyHeap dump; deployment metadata, diagnosis rules, thresholds,
and user-facing conclusions belong to the consuming tool.

## Commands

Generate a summary without calculating inbound references or retained heap:

```bash
PYTHONPATH=src poetry run python -m analyzer summary --file heap.pyheap
```

Generate the same document with retained heap populated:

```bash
PYTHONPATH=src poetry run python -m analyzer retained-heap \
  --file heap.pyheap --top-n 100 --format json
```

JSON is written to stdout. Progress and diagnostic logs are written to stderr, so
stdout can be redirected or consumed as a machine protocol without filtering.

## Document shape

```json
{
  "schema": "pyheap.analysis/v1",
  "source": {
    "sha256": "...",
    "size_bytes": 1024,
    "heap_format_version": 1,
    "created_at": "2026-07-21T09:00:51+00:00",
    "with_string_representations": false
  },
  "heap": {
    "object_count": 3,
    "type_count": 2,
    "thread_count": 1,
    "referent_count": 1,
    "shallow_size_bytes": 220
  },
  "types": [
    {
      "type_address": "0x10",
      "type_name": "dict",
      "object_count": 2,
      "shallow_size_bytes": 120
    }
  ],
  "threads": [
    {
      "name": "MainThread",
      "is_alive": true,
      "is_daemon": false,
      "retained_size_bytes": null,
      "frames": []
    }
  ],
  "retained_heap": {
    "status": "not_computed",
    "top_n": 100,
    "top_objects": []
  }
}
```

## Semantics

- All sizes are integer bytes.
- Object and type addresses are hexadecimal strings. JSON numbers cannot exactly
  represent every unsigned 64-bit address in all consumer languages.
- `types` is ordered by shallow size descending, then object count descending,
  type name, and address. Entries remain separate when distinct type objects have
  the same name.
- Thread frame order is the order captured in the dump. Local variables are sorted
  by name for deterministic output. A local referring to an object absent from the
  filtered heap has `type_name: null`.
- `retained_heap.status: not_computed` means no retained calculation was attempted;
  an empty `top_objects` list must not be interpreted as a zero retained heap.
- `retained_heap.status: complete` means retained sizes were calculated for the
  captured heap. `top_objects` contains at most `top_n` entries, ordered by retained
  size descending.
- Retained top objects include an optional `container_profile`. For built-in dicts
  it reports the item count plus key/value type histograms; built-in lists, sets,
  and tuples report the item count plus an element type histogram. Histograms are
  bounded and never include element string values.
- Retained top objects include bounded `inbound_reference_paths`. Each path starts
  at a direct owner and contains object address/type pairs, stopping at a module,
  three edges, or an object-graph root. The field is empty when inbound references
  were not supplied by the caller.
- `string_representation` is `null` when the dump was captured without string
  representations.
- Shallow and retained sizes describe objects captured by PyHeap. They are not
  process RSS/PSS and do not include every native allocation.

## Compatibility

Consumers must select behavior by the exact `schema` value and ignore unknown
fields. Backward-compatible additions may be made within `pyheap.analysis/v1`.
Removing a field, renaming a field, changing its JSON type, or changing its meaning
requires a new schema version.

The protocol deliberately does not include the local heap file path. `source.sha256`
and `source.size_bytes` identify the artifact without leaking machine-specific paths.
Consumers that associate a dump with a pod, process, incident, or other external
target should keep that provenance in their own manifest.

Stack file names, local variable names, and optional string representations can
contain application information. Treat the JSON output with the same access controls
as the source heap dump.
