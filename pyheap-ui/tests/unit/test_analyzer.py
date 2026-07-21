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
import argparse
import json
from unittest.mock import MagicMock, patch

import analyzer


def test_summary_writes_only_analysis_json(capsys) -> None:
    heap = MagicMock()
    analysis = {"schema": "pyheap.analysis/v1"}

    with patch.object(analyzer, "_load_heap", return_value=heap), patch.object(
        analyzer, "build_heap_analysis", return_value=analysis
    ) as build:
        analyzer.summary(argparse.Namespace(file="heap.pyheap"))

    assert json.loads(capsys.readouterr().out) == analysis
    build.assert_called_once_with(heap_file_name="heap.pyheap", heap=heap)


def test_retained_heap_json_uses_same_protocol(capsys) -> None:
    heap = MagicMock()
    heap.objects = {}
    retained = MagicMock()
    inbound_references = MagicMock()
    analysis = {"schema": "pyheap.analysis/v1", "retained_heap": {"status": "complete"}}

    with patch.object(analyzer, "_load_heap", return_value=heap), patch.object(
        analyzer, "InboundReferences", return_value=inbound_references
    ), patch.object(
        analyzer, "provide_retained_heap_with_caching", return_value=retained
    ), patch.object(
        analyzer, "build_heap_analysis", return_value=analysis
    ) as build:
        analyzer.retained_heap(
            argparse.Namespace(
                file="heap.pyheap",
                format="json",
                top_n=7,
            )
        )

    assert json.loads(capsys.readouterr().out) == analysis
    build.assert_called_once_with(
        heap_file_name="heap.pyheap",
        heap=heap,
        retained_heap=retained,
        inbound_references=inbound_references,
        top_n=7,
    )


def test_retained_heap_keeps_text_as_default_format() -> None:
    args = analyzer.parser.parse_args(["retained-heap", "--file", "heap.pyheap"])

    assert args.format == "text"
