#
# Copyright 2022 Ivan Yurchenko
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from __future__ import annotations

import hashlib
import os
from collections import Counter, deque
from typing import Any, Dict, List, Optional

from pyheap_ui.heap import (
    InboundReferences,
    RetainedHeap,
    objects_sorted_by_retained_heap,
    total_heap_size,
)
from pyheap_ui.heap_types import Address, Heap, HeapObject, HeapThread


ANALYSIS_SCHEMA = "pyheap.analysis/v1"
OWNER_TYPE_LIMIT = 20
INBOUND_PATH_LIMIT = 10
INBOUND_PATH_DEPTH = 3


def _address(value: Address) -> str:
    # JSON numbers cannot represent every unsigned 64-bit address exactly. Hex strings
    # preserve identity across languages while making the value recognizable to humans.
    return f"0x{value:x}"


def _sha256(file_name: str) -> str:
    digest = hashlib.sha256()
    with open(file_name, "rb") as f:
        while chunk := f.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _type_summaries(heap: Heap) -> List[Dict[str, Any]]:
    counts: Dict[Address, int] = {}
    shallow_sizes: Dict[Address, int] = {}
    for obj in heap.objects.values():
        counts[obj.type] = counts.get(obj.type, 0) + 1
        shallow_sizes[obj.type] = shallow_sizes.get(obj.type, 0) + obj.size

    type_addresses = sorted(
        counts,
        key=lambda type_address: (
            -shallow_sizes[type_address],
            -counts[type_address],
            heap.types[type_address],
            type_address,
        ),
    )
    return [
        {
            "type_address": _address(type_address),
            "type_name": heap.types[type_address],
            "object_count": counts[type_address],
            "shallow_size_bytes": shallow_sizes[type_address],
        }
        for type_address in type_addresses
    ]


def _object_type_name(heap: Heap, address: Address) -> Optional[str]:
    obj = heap.objects.get(address)
    if obj is None:
        return None
    return heap.types.get(obj.type)


def _thread_summary(
    heap: Heap,
    thread: HeapThread,
    retained_heap: Optional[RetainedHeap],
) -> Dict[str, Any]:
    frames = []
    for frame in thread.stack_trace:
        local_variables = [
            {
                "name": name,
                "object_address": _address(address),
                "type_name": _object_type_name(heap, address),
            }
            for name, address in sorted(frame.locals.items())
        ]
        frames.append(
            {
                "file_name": frame.co_filename,
                "line_number": frame.lineno,
                "function_name": frame.co_name,
                "local_variables": local_variables,
            }
        )

    return {
        "name": thread.name,
        "is_alive": thread.is_alive,
        "is_daemon": thread.is_daemon,
        "retained_size_bytes": (
            retained_heap.get_for_thread(thread.name)
            if retained_heap is not None
            else None
        ),
        "frames": frames,
    }


def _string_representation(heap: Heap, obj: HeapObject) -> Optional[str]:
    if not heap.header.flags.with_str_repr:
        return None
    return obj.str_repr


def _type_histogram(heap: Heap, addresses) -> List[Dict[str, Any]]:
    counts = Counter(
        heap.types[heap.objects[address].type]
        for address in addresses
        if address in heap.objects
    )
    return [
        {"type_name": type_name, "object_count": object_count}
        for type_name, object_count in sorted(
            counts.items(), key=lambda item: (-item[1], item[0])
        )[:OWNER_TYPE_LIMIT]
    ]


def _container_profile(heap: Heap, obj: HeapObject) -> Optional[Dict[str, Any]]:
    if isinstance(obj.content, dict):
        return {
            "item_count": len(obj.content),
            "key_types": _type_histogram(heap, obj.content.keys()),
            "value_types": _type_histogram(heap, obj.content.values()),
        }
    if isinstance(obj.content, (list, set, tuple)):
        return {
            "item_count": len(obj.content),
            "element_types": _type_histogram(heap, obj.content),
        }
    return None


def _inbound_reference_paths(
    heap: Heap,
    inbound_references: Optional[InboundReferences],
    address: Address,
) -> List[List[Dict[str, Any]]]:
    if inbound_references is None:
        return []

    paths: List[List[Dict[str, Any]]] = []
    pending = deque([(address, [], {address})])
    while pending and len(paths) < INBOUND_PATH_LIMIT:
        current, path, seen = pending.popleft()
        parents = sorted(inbound_references[current])
        if not parents:
            if path:
                paths.append(path)
            continue

        for parent_address in parents:
            if len(paths) >= INBOUND_PATH_LIMIT:
                break
            parent = heap.objects.get(parent_address)
            if parent is None:
                continue
            parent_node = {
                "object_address": _address(parent_address),
                "type_name": heap.types[parent.type],
            }
            next_path = [*path, parent_node]
            if (
                parent_address in seen
                or len(next_path) >= INBOUND_PATH_DEPTH
                or parent_node["type_name"] == "module"
            ):
                paths.append(next_path)
            else:
                pending.append((parent_address, next_path, seen | {parent_address}))
    return paths


def _retained_heap_summary(
    heap: Heap,
    retained_heap: Optional[RetainedHeap],
    inbound_references: Optional[InboundReferences],
    top_n: int,
) -> Dict[str, Any]:
    if retained_heap is None:
        return {
            "status": "not_computed",
            "top_n": top_n,
            "top_objects": [],
        }

    top_objects = []
    for address, retained_size in objects_sorted_by_retained_heap(heap, retained_heap)[
        :top_n
    ]:
        obj = heap.objects[address]
        top_objects.append(
            {
                "object_address": _address(address),
                "type_name": heap.types[obj.type],
                "shallow_size_bytes": obj.size,
                "retained_size_bytes": retained_size,
                "string_representation": _string_representation(heap, obj),
                "container_profile": _container_profile(heap, obj),
                "inbound_reference_paths": _inbound_reference_paths(
                    heap, inbound_references, address
                ),
            }
        )

    return {
        "status": "complete",
        "top_n": top_n,
        "top_objects": top_objects,
    }


def build_heap_analysis(
    *,
    heap_file_name: str,
    heap: Heap,
    retained_heap: Optional[RetainedHeap] = None,
    inbound_references: Optional[InboundReferences] = None,
    top_n: int = 100,
) -> Dict[str, Any]:
    """Build the stable, consumer-neutral JSON representation of a heap analysis."""
    return {
        "schema": ANALYSIS_SCHEMA,
        "source": {
            "sha256": _sha256(heap_file_name),
            "size_bytes": os.path.getsize(heap_file_name),
            "heap_format_version": heap.header.version,
            "created_at": heap.header.created_at,
            "with_string_representations": heap.header.flags.with_str_repr,
        },
        "heap": {
            "object_count": len(heap.objects),
            "type_count": len(heap.types),
            "thread_count": len(heap.threads),
            "referent_count": sum(len(obj.referents) for obj in heap.objects.values()),
            "shallow_size_bytes": total_heap_size(heap),
        },
        "types": _type_summaries(heap),
        "threads": [
            _thread_summary(heap, thread, retained_heap) for thread in heap.threads
        ],
        "retained_heap": _retained_heap_summary(
            heap, retained_heap, inbound_references, top_n
        ),
    }
