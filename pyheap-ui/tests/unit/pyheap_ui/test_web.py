from pyheap_ui import __main__ as web
from pyheap_ui.heap import InboundReferences, RetainedHeap
from pyheap_ui.heap_types import Heap, HeapFlags, HeapHeader, HeapObject


def test_object_page_handles_heap_without_string_representations(monkeypatch) -> None:
    dict_type = 0x10
    obj = HeapObject(address=0x100, type=dict_type, size=64, referents=set())
    obj.set_read_attributes_func(0, lambda _: {})
    obj._str_repr_func = lambda _: None
    heap = Heap(
        header=HeapHeader(
            version=1,
            created_at="2026-07-21T09:00:51+00:00",
            flags=HeapFlags(with_str_repr=False),
            well_known_types={
                "dict": dict_type,
                "list": 0x11,
                "set": 0x12,
                "tuple": 0x13,
            },
        ),
        threads=[],
        objects={obj.address: obj},
        types={dict_type: "dict"},
    )
    monkeypatch.setattr(web, "heap", heap)
    monkeypatch.setattr(web, "inbound_references", InboundReferences(heap.objects))
    monkeypatch.setattr(
        web,
        "retained_heap",
        RetainedHeap(object_retained_heap={obj.address: 64}, thread_retained_heap={}),
    )
    web.well_known_container_types.cache_clear()

    response = web.app.test_client().get(f"/objects/{obj.address}")

    assert response.status_code == 200
    assert b"Not captured" in response.data
