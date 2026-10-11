import json

import pytest

from fleasion.fflags import (
    FFlagModifier,
    ProfileManager,
    Settings,
    normalize_custom_fflags,
)


def test_normalize_values():
    assert normalize_custom_fflags({' A ': True, 'B': 5, 'C': 1.5, 'D': 'x', '': 'skip', 'E': None, 'F': [1]}) == {
        'A': 'True',
        'B': '5',
        'C': '1.5',
        'D': 'x',
    }
    assert normalize_custom_fflags([1, 2]) == {}


def test_settings_roundtrip_preserves_unknown_keys(tmp_path):
    path = tmp_path / 'settings.json'
    path.write_text(json.dumps({'theme': 'dark', 'custom_fflags': {'FFlagA': 'True'}}))
    settings = Settings(path)
    settings.enabled = True
    settings.disabled = ['FFlagA', ' ', 'FFlagA']
    settings.flags = {**settings.flags, 'DFIntB': 7}
    settings.save()
    data = json.loads(path.read_text())
    assert data['theme'] == 'dark'
    assert data['custom_fflags'] == {'FFlagA': 'True', 'DFIntB': '7'}
    assert data['custom_fflag_disabled'] == ['FFlagA']
    assert data['custom_fflags_enabled'] is True


def test_settings_corrupt_file_is_empty(tmp_path):
    path = tmp_path / 'settings.json'
    path.write_text('{not json')
    settings = Settings(path)
    assert settings.flags == {} and settings.enabled is False


def test_runtime_flags_exclude_disabled_and_add_companion(tmp_path):
    settings = Settings(tmp_path / 's.json')
    settings.flags = {'A': '1', 'B': '2'}
    settings.disabled = ['B']
    flags = FFlagModifier(settings).runtime_flags()
    assert flags == {'A': '1', 'DFIntSecondsBetweenDynamicVariableReloading': '1'}


def test_companion_overrides_saved_value(tmp_path):
    settings = Settings(tmp_path / 's.json')
    settings.flags = {'DFIntSecondsBetweenDynamicVariableReloading': '120'}
    assert FFlagModifier(settings).runtime_flags()['DFIntSecondsBetweenDynamicVariableReloading'] == '1'


def test_modify_response_edge_cases(tmp_path):
    settings = Settings(tmp_path / 's.json')
    settings.enabled = True
    settings.flags = {'A': '1'}
    modifier = FFlagModifier(settings)
    path = '/v2/settings/application/PCDesktopClient'
    assert modifier.modify_response(path, b'not json') == b'not json'
    assert modifier.modify_response(path, b'[]') == b'[]'
    assert modifier.modify_response(path, b'{"x":1}') == b'{"x":1}'
    assert modifier.modify_response('/other', b'{"applicationSettings":{}}') == b'{"applicationSettings":{}}'


def _write_cache(path, settings, signature=b'SIG', compression=0):
    payload = json.dumps({'applicationSettings': settings}, separators=(',', ':')).encode()
    path.write_bytes(len(signature).to_bytes(4, 'little') + signature + bytes([compression]) + payload)


def _read_cache(path):
    raw = path.read_bytes()
    offset = 4 + int.from_bytes(raw[:4], 'little') + 1
    return json.loads(raw[offset:])['applicationSettings'], raw[:offset]


def test_prime_flag_cache_adds_and_removes(tmp_path):
    cache = tmp_path / 'flag_cache.dat'
    _write_cache(cache, {'Existing': 'x'})
    settings = Settings(tmp_path / 's.json')
    settings.enabled = True
    settings.flags = {'DFIntTaskSchedulerTargetFps': '240'}
    modifier = FFlagModifier(settings, flag_cache_path=cache)

    assert modifier.prime_flag_cache() is True
    flags, header = _read_cache(cache)
    assert flags['DFIntTaskSchedulerTargetFps'] == '240' and flags['Existing'] == 'x'
    assert header == (3).to_bytes(4, 'little') + b'SIG' + b'\x00'
    assert modifier.prime_flag_cache() is False  # không đổi -> không ghi lại

    settings.enabled = False
    assert modifier.prime_flag_cache() is True
    flags, _ = _read_cache(cache)
    assert flags == {'Existing': 'x'}


def test_prime_flag_cache_ignores_compressed_or_missing(tmp_path):
    settings = Settings(tmp_path / 's.json')
    settings.enabled = True
    modifier = FFlagModifier(settings, flag_cache_path=tmp_path / 'missing.dat')
    assert modifier.prime_flag_cache() is False
    cache = tmp_path / 'c.dat'
    _write_cache(cache, {}, compression=1)
    before = cache.read_bytes()
    assert FFlagModifier(settings, flag_cache_path=cache).prime_flag_cache() is False
    assert cache.read_bytes() == before


def test_profiles(tmp_path):
    profiles = ProfileManager(tmp_path / 'p')
    assert profiles.list_profiles() == []
    assert profiles.save('Low End.json', {'A': True}) == 'Low End'
    assert profiles.load('Low End') == {'A': 'True'}
    assert profiles.rename('Low End', 'Potato') == 'Potato'
    profiles.save('zeta', {})
    assert profiles.list_profiles() == ['Potato', 'zeta']
    with pytest.raises(ValueError):
        profiles.rename('zeta', 'Potato')
    with pytest.raises(ValueError):
        profiles.save('a/b', {})
    with pytest.raises(ValueError):
        profiles.load('nope')
    (tmp_path / 'p' / 'bad.json').write_text('{"A": [1]}')
    with pytest.raises(ValueError):
        profiles.load('bad')
    profiles.delete('zeta')
    with pytest.raises(ValueError):
        profiles.delete('zeta')
