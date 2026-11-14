"""The parsed SLEIGH specification is cached on disk between runs.

Most tests use a tiny synthetic specification so a cache miss is cheap; one
test round-trips the real x86-64 specification to prove the cached state is
semantically identical.  Every test points the cache at ``tmp_path``, so the
real temporary-directory cache is never read or written.
"""

from __future__ import annotations

from pathlib import Path
import pickle

import pytest

import cache
from isa.sleigher import sla
from isa.sleigher.x86_sleigher import DEFAULT_SPEC_PATH


@pytest.fixture
def cache_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "cache"
    monkeypatch.setattr(cache, "CACHE_ROOT", root)
    return root


def _synthetic_root() -> sla.SlaElement:
    """Return the smallest specification ``SlaSpec._parse`` accepts."""
    head = sla.SlaElement(
        sla.E_SUBTABLE_SYM_HEAD,
        {sla.A_ID: 0, sla.A_NAME: "instruction", sla.A_SCOPE: 0},
    )
    content = sla.SlaElement(sla.E_SUBTABLE_SYM, {sla.A_ID: 0})
    return sla.SlaElement(
        sla.E_SLEIGH,
        {},
        [
            sla.SlaElement(sla.E_SPACES, {sla.A_DEFAULTSPACE: "ram"}),
            sla.SlaElement(sla.E_SYMBOL_TABLE, {}, [head, content]),
        ],
    )


@pytest.fixture
def synthetic(monkeypatch: pytest.MonkeyPatch) -> list[Path]:
    """Replace the packed reader with the synthetic tree and record calls."""
    calls: list[Path] = []

    def decode(path: str | Path) -> sla.SlaElement:
        calls.append(Path(path))
        return _synthetic_root()

    monkeypatch.setattr(sla, "decode_sla", decode)
    return calls


@pytest.fixture
def spec_path(tmp_path: Path) -> Path:
    path = tmp_path / "synthetic.sla"
    path.write_bytes(b"synthetic specification")
    return path


def _entry(data: bytes) -> Path:
    return cache.entry_path("sla", sla._cache_key(data), ".pickle")


def _persisted_state(spec: sla.SlaSpec) -> dict:
    """Return the part of a spec's state that the cache stores."""
    return {
        key: value
        for key, value in spec.__dict__.items()
        if key not in ("path", "_resolve_cached", "_state_effects_cache")
    }


def test_parse_cache_lives_under_the_shared_root(
    cache_root: Path, synthetic, spec_path: Path
) -> None:
    sla.SlaSpec(spec_path)

    entry = _entry(spec_path.read_bytes())
    assert entry.is_file()
    assert entry.is_relative_to(cache_root)


def test_gpu_and_sla_caches_share_one_root() -> None:
    import gpu.backend

    assert gpu.backend.CACHE_ROOT == cache.CACHE_ROOT


def test_second_parse_reuses_the_cached_state(
    cache_root: Path, synthetic, spec_path: Path
) -> None:
    first = sla.SlaSpec(spec_path)
    entry = _entry(spec_path.read_bytes())
    before = entry.stat().st_mtime_ns

    second = sla.SlaSpec(spec_path)

    assert len(synthetic) == 1
    assert entry.stat().st_mtime_ns == before
    assert _persisted_state(second) == _persisted_state(first)


def test_cached_state_decodes_identically(cache_root: Path) -> None:
    fresh = sla.SlaSpec(DEFAULT_SPEC_PATH)
    cached = sla.SlaSpec(DEFAULT_SPEC_PATH)

    defaults = {"longMode": 1, "addrsize": 2, "opsize": 1}
    context = fresh.build_context(defaults)

    assert cached.build_context(defaults) == context
    assert _persisted_state(cached) == _persisted_state(fresh)
    for encoding in ("488b442408", "e800000000", "7500", "c3", "0f0b"):
        data = bytes.fromhex(encoding)
        assert cached.resolve(data, context) == fresh.resolve(data, context)
    assert cached.all_state_spaces() == fresh.all_state_spaces()
    assert cached.root_subtable is not None
    assert cached.root_subtable.name == "instruction"


def test_cache_key_depends_on_the_parsed_bytes() -> None:
    data = b"one specification"

    assert sla._cache_key(data) != sla._cache_key(data + b"\x00")
    assert sla._cache_key(data) == sla._cache_key(bytes(data))


def test_a_different_specification_gets_its_own_entry(
    cache_root: Path, synthetic, tmp_path: Path
) -> None:
    original = tmp_path / "original.sla"
    extended = tmp_path / "extended.sla"
    original.write_bytes(b"specification")
    extended.write_bytes(b"specification\x00")

    sla.SlaSpec(original)
    sla.SlaSpec(extended)

    assert _entry(original.read_bytes()).is_file()
    assert _entry(extended.read_bytes()).is_file()
    assert _entry(original.read_bytes()) != _entry(extended.read_bytes())


@pytest.mark.parametrize(
    "payload",
    [
        b"not a pickle",
        b"",
        pickle.dumps({"version": sla._CACHE_VERSION, "state": {}}),
        pickle.dumps(
            {
                "version": sla._CACHE_VERSION,
                "source": "0" * 64,
                "state": {"root_subtable": None},
            }
        ),
    ],
    ids=["garbage", "empty", "no-source", "wrong-source"],
)
def test_unusable_cache_entries_fall_back_to_parsing(
    cache_root: Path, synthetic, spec_path: Path, payload: bytes
) -> None:
    entry = _entry(spec_path.read_bytes())
    entry.parent.mkdir(parents=True)
    entry.write_bytes(payload)

    spec = sla.SlaSpec(spec_path)

    assert len(synthetic) == 1
    assert spec.root_subtable is not None
    with entry.open("rb") as stream:
        stored = pickle.load(stream)
    assert stored["source"] == sla._source_digest()
    assert isinstance(stored["state"], dict)


def test_corrupt_specification_does_not_write_a_cache_entry(
    cache_root: Path, tmp_path: Path
) -> None:
    broken = tmp_path / "broken.sla"
    broken.write_bytes(b"sla\x04 definitely not zlib")

    with pytest.raises(sla.SlaError):
        sla.SlaSpec(broken)

    assert not (cache_root / "sla").exists()


def test_cache_write_leaves_no_temporary_file(
    cache_root: Path, synthetic, spec_path: Path
) -> None:
    sla.SlaSpec(spec_path)

    entries = list((cache_root / "sla").iterdir())

    assert [entry.name for entry in entries] == [
        _entry(spec_path.read_bytes()).name
    ]


def test_unwritable_cache_does_not_fail_the_parse(
    cache_root: Path,
    synthetic,
    spec_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def refuse(path: Path, state: dict) -> None:
        raise OSError("read-only cache")

    monkeypatch.setattr(sla, "_store_cached_state", refuse)

    spec = sla.SlaSpec(spec_path)

    assert spec.root_subtable is not None
    assert not (cache_root / "sla").exists()


def test_cache_replace_cleans_up_a_failed_write(tmp_path: Path) -> None:
    target = tmp_path / "entry.pickle"

    def writer(temporary: Path) -> None:
        temporary.write_bytes(b"partial")
        raise RuntimeError("writer failed")

    with pytest.raises(RuntimeError):
        cache.replace(target, writer)

    assert not target.exists()
    assert list(tmp_path.iterdir()) == []
