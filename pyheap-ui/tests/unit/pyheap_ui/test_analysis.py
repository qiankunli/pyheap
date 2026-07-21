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
import hashlib

from pyheap_ui.analysis import ANALYSIS_SCHEMA, build_heap_analysis
from pyheap_ui.heap import InboundReferences, RetainedHeap
from pyheap_ui.heap_types import (
    Heap,
    HeapFlags,
    HeapHeader,
    HeapObject,
    HeapThread,
    HeapThreadFrame,
)


DICT_TYPE = 0x10
STRING_TYPE = 0x20
FILE_FINDER_TYPE = 0x30
MODULE_TYPE = 0x40


def _heap() -> Heap:
    return Heap(
        header=HeapHeader(
            version=1,
            created_at="2026-07-21T09:00:51+00:00",
            flags=HeapFlags(with_str_repr=False),
            well_known_types={},
        ),
        threads=[
            HeapThread(
                name="MainThread",
                is_alive=True,
                is_daemon=False,
                stack_trace=[
                    HeapThreadFrame(
                        co_filename="/app/main.py",
                        lineno=42,
                        co_name="run",
                        locals={"payload": 0x101, "missing": 0x999},
                    )
                ],
            )
        ],
        objects={
            0x100: HeapObject(
                address=0x100,
                type=DICT_TYPE,
                size=80,
                referents={0x101},
            ),
            0x101: HeapObject(
                address=0x101,
                type=STRING_TYPE,
                size=100,
                referents=set(),
            ),
            0x102: HeapObject(
                address=0x102,
                type=DICT_TYPE,
                size=40,
                referents=set(),
            ),
        },
        types={DICT_TYPE: "dict", STRING_TYPE: "str"},
    )


def test_build_summary_analysis(tmp_path) -> None:
    heap_file = tmp_path / "heap.pyheap"
    heap_file.write_bytes(b"heap contents")

    result = build_heap_analysis(heap_file_name=str(heap_file), heap=_heap(), top_n=5)

    assert result["schema"] == ANALYSIS_SCHEMA
    assert result["source"] == {
        "sha256": hashlib.sha256(b"heap contents").hexdigest(),
        "size_bytes": 13,
        "heap_format_version": 1,
        "created_at": "2026-07-21T09:00:51+00:00",
        "with_string_representations": False,
    }
    assert result["heap"] == {
        "object_count": 3,
        "type_count": 2,
        "thread_count": 1,
        "referent_count": 1,
        "shallow_size_bytes": 220,
    }
    assert result["types"] == [
        {
            "type_address": "0x10",
            "type_name": "dict",
            "object_count": 2,
            "shallow_size_bytes": 120,
        },
        {
            "type_address": "0x20",
            "type_name": "str",
            "object_count": 1,
            "shallow_size_bytes": 100,
        },
    ]
    assert result["threads"] == [
        {
            "name": "MainThread",
            "is_alive": True,
            "is_daemon": False,
            "retained_size_bytes": None,
            "frames": [
                {
                    "file_name": "/app/main.py",
                    "line_number": 42,
                    "function_name": "run",
                    "local_variables": [
                        {
                            "name": "missing",
                            "object_address": "0x999",
                            "type_name": None,
                        },
                        {
                            "name": "payload",
                            "object_address": "0x101",
                            "type_name": "str",
                        },
                    ],
                }
            ],
        }
    ]
    assert result["retained_heap"] == {
        "status": "not_computed",
        "top_n": 5,
        "top_objects": [],
    }


def test_build_retained_heap_analysis(tmp_path) -> None:
    heap_file = tmp_path / "heap.pyheap"
    heap_file.write_bytes(b"heap contents")
    heap = _heap()
    heap.objects[0x103] = HeapObject(
        address=0x103,
        type=FILE_FINDER_TYPE,
        size=64,
        referents=set(),
    )
    heap.objects[0x100].content = {0x101: 0x103}
    heap.objects[0x100].referents.add(0x103)
    heap.objects[0x104] = HeapObject(
        address=0x104,
        type=DICT_TYPE,
        size=48,
        referents={0x100},
    )
    heap.objects[0x105] = HeapObject(
        address=0x105,
        type=MODULE_TYPE,
        size=72,
        referents={0x104},
    )
    heap.types.update({FILE_FINDER_TYPE: "FileFinder", MODULE_TYPE: "module"})
    retained_heap = RetainedHeap(
        object_retained_heap={0x100: 220, 0x101: 100, 0x102: 40},
        thread_retained_heap={"MainThread": 100},
    )

    result = build_heap_analysis(
        heap_file_name=str(heap_file),
        heap=heap,
        retained_heap=retained_heap,
        inbound_references=InboundReferences(heap.objects),
        top_n=2,
    )

    assert result["threads"][0]["retained_size_bytes"] == 100
    assert result["retained_heap"] == {
        "status": "complete",
        "top_n": 2,
        "top_objects": [
            {
                "object_address": "0x100",
                "type_name": "dict",
                "shallow_size_bytes": 80,
                "retained_size_bytes": 220,
                "string_representation": None,
                "container_profile": {
                    "item_count": 1,
                    "key_types": [{"type_name": "str", "object_count": 1}],
                    "value_types": [{"type_name": "FileFinder", "object_count": 1}],
                },
                "inbound_reference_paths": [
                    [
                        {"object_address": "0x104", "type_name": "dict"},
                        {"object_address": "0x105", "type_name": "module"},
                    ]
                ],
            },
            {
                "object_address": "0x101",
                "type_name": "str",
                "shallow_size_bytes": 100,
                "retained_size_bytes": 100,
                "string_representation": None,
                "container_profile": None,
                "inbound_reference_paths": [
                    [
                        {"object_address": "0x100", "type_name": "dict"},
                        {"object_address": "0x104", "type_name": "dict"},
                        {"object_address": "0x105", "type_name": "module"},
                    ]
                ],
            },
        ],
    }
