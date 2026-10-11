from fleasion import winsys
from fleasion.certs import generate_ca

HOSTS = {'clientsettings.roblox.com', 'clientsettingscdn.roblox.com'}
ORIGINAL = '127.0.0.1 localhost\n# comment\n10.0.0.5 nas.local\n'


def test_hosts_add_remove_roundtrip(tmp_path):
    hosts = tmp_path / 'hosts'
    hosts.write_text(ORIGINAL)
    winsys.add_hosts_entries(HOSTS, hosts)
    text = hosts.read_text()
    assert text.startswith(ORIGINAL)
    for host in HOSTS:
        assert f'127.0.0.1 {host} {winsys.HOSTS_MARKER}' in text
    assert winsys.has_stale_hosts_entries(hosts)

    winsys.add_hosts_entries(HOSTS, hosts)  # gọi lại không nhân đôi
    assert hosts.read_text().count(winsys.HOSTS_MARKER) == 2

    assert winsys.remove_hosts_entries(hosts) is True
    assert hosts.read_text() == ORIGINAL
    assert not winsys.has_stale_hosts_entries(hosts)


def test_hosts_conflicts_detected(tmp_path):
    hosts = tmp_path / 'hosts'
    hosts.write_text('1.2.3.4 clientsettings.roblox.com\n127.0.0.1 clientsettingscdn.roblox.com\n')
    conflicts = winsys.hosts_conflicts(HOSTS, hosts)
    assert conflicts == ['1.2.3.4 clientsettings.roblox.com']


def test_remove_on_clean_hosts_does_not_touch_file(tmp_path):
    hosts = tmp_path / 'hosts'
    hosts.write_text(ORIGINAL)
    mtime = hosts.stat().st_mtime_ns
    assert winsys.remove_hosts_entries(hosts) is True
    assert hosts.stat().st_mtime_ns == mtime


def test_cacert_flow_with_non_fleasion_roots(tmp_path):
    # Tạo 2 chứng chỉ gốc "thường" (không phải Fleasion) để mô phỏng cacert.pem của Roblox.
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    def make_root(cn):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
        now = datetime.datetime.now(datetime.timezone.utc)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=30))
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.PEM).decode()

    roots = make_root('Root One') + make_root('Root Two')
    ca_cert, _ = generate_ca(tmp_path / 'ca')
    ca_pem = ca_cert.read_text()

    install = tmp_path / 'version-1'
    (install / 'ssl').mkdir(parents=True)
    ca_file = install / 'ssl' / 'cacert.pem'
    ca_file.write_text(roots)

    assert winsys.cacert_state(ca_file, ca_pem) == 'missing-ca'
    assert winsys.install_ca_into_roblox(ca_pem, [install]) == (1, 0)
    assert winsys.cacert_state(ca_file, ca_pem) == 'current'
    assert winsys.install_ca_into_roblox(ca_pem, [install]) == (0, 0)  # idempotent
    assert ca_file.read_text().count('BEGIN CERTIFICATE') == 3

    assert winsys.remove_ca_from_roblox([install], ca_pem) == 1
    assert ca_file.read_text().count('BEGIN CERTIFICATE') == 2

    # cacert.pem hỏng/không có thì không bị ghi đè bằng mỗi CA của ta.
    empty = tmp_path / 'version-2'
    (empty / 'ssl').mkdir(parents=True)
    (empty / 'ssl' / 'cacert.pem').write_text('')
    assert winsys.install_ca_into_roblox(ca_pem, [empty]) == (0, 1)
    assert (empty / 'ssl' / 'cacert.pem').read_text() == ''
    assert winsys.install_ca_into_roblox(ca_pem, [tmp_path / 'nope']) == (0, 0)
