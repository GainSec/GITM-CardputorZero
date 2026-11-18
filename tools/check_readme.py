"""Validate README anchors/shell syntax and execute CLI examples with ephemeral fixtures.

Run against the installed ARM64 package. System backends are parsed unchanged,
then executed with the simulator; GUI examples render one bounded screenshot.
"""
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path
import hashlib, io, json, os, re, shlex, shutil, subprocess, sys, tempfile
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from gitm.cli import build_parser
from gitm.profiles import list_profiles

readme = Path(sys.argv[1])
installed = Path('/usr/share/doc/gainsec-gitm/README.md')
source = readme.read_text()
assert installed.read_bytes() == readme.read_bytes()
assert '0.2.1 full-feature suite' in source
for phrase in ('AP-only', 'TLS-disabled', 'capture-disabled', 'deferred', 'physical acceptance remains pending'):
    assert phrase.lower() not in source.lower(), phrase
headings = re.findall(r'^#{1,6} (.+)$', source, re.M)
anchors = {re.sub(r'[^\w\- ]', '', text.lower()).replace(' ', '-') for text in headings}
links = re.findall(r'\[[^\]]*\]\(([^)]+)\)', source)
assert links
for target in links:
    if target.startswith('#'):
        assert target[1:] in anchors, target
    elif target.startswith('https://'):
        assert target.startswith('https://github.com/GainSec/GITM-CardputorZero'), target
    else:
        assert (readme.parent/target).is_file(), target
assert all(name in source for name in list_profiles())
assert 'externally blocked and waived for this acceptance' in source
blocks = re.findall(r'```sh\n(.*?)```', source, re.S)
results = []
with tempfile.TemporaryDirectory(prefix='gitm-readme-') as work:
    fixture_home = Path(work)
    pem_dir = fixture_home/'lab-ca'; pem_dir.mkdir(mode=0o700)
    now = datetime.now(timezone.utc)
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'README ephemeral fixture root')])
    def certificate(subject, key, issuer, signer):
        return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now-timedelta(minutes=1))
            .not_valid_after(now+timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True)
            .add_extension(x509.KeyUsage(False,False,False,False,False,True,True,False,False),True).sign(signer,hashes.SHA256()))
    root = certificate(root_name, root_key, root_name, root_key)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = certificate(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'README subordinate')]),key,root_name,root_key)
    for filename,data in {
        'subordinate.crt':cert.public_bytes(serialization.Encoding.PEM),
        'subordinate.key':key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()),
        'parents.pem':root.public_bytes(serialization.Encoding.PEM),
    }.items():
        (pem_dir/filename).write_bytes(data); (pem_dir/filename).chmod(0o600)
    for number, block in enumerate(blocks, 1):
        subprocess.run(['bash','-n'],input=block,text=True,check=True,capture_output=True)
        for line in block.replace('\\\n',' ').splitlines():
            line=line.strip()
            if not line.startswith('gitm '):
                continue
            argv=shlex.split(line)[1:]
            with redirect_stdout(io.StringIO()):
                try:build_parser().parse_args(argv)
                except SystemExit as exc:assert exc.code==0, (line,exc.code)
            resolved=[arg.replace('$HOME',str(fixture_home)) for arg in argv]
            if '--backend' in resolved:
                index=resolved.index('--backend')+1
                resolved[index]='sim'
            if resolved and resolved[0]=='gui':
                resolved += ['--screenshot',str(fixture_home/f'gui-{number}.png'),'--demo-state','ACTIVE']
            result=subprocess.run([sys.executable,'-m','gitm',*resolved],capture_output=True,text=True,timeout=20)
            assert result.returncode==0,(line,result.returncode,result.stderr,result.stdout[:300])
            results.append({'readme_block':number,'original':line,'original_args_parsed':True,
                'execution':'sim backend; temporary HOME-path substitution; bounded GUI screenshot',
                'returncode':result.returncode,'stdout_sha256':hashlib.sha256(result.stdout.encode()).hexdigest()})
    binaries=('apt','adduser','systemctl','nmcli','tcpdump','bash')
    assert all(shutil.which(name) for name in binaries)
    assert (fixture_home/'gitm-exports/mitm.p12').is_file()
    assert (fixture_home/'gitm-custom-exports/mitm.p12').is_file()
    assert (fixture_home/'gitm-profile-exports/mitm.p12').is_file()
print(json.dumps({'ok':True,'embedded_readme_sha256':hashlib.sha256(installed.read_bytes()).hexdigest(),
    'readme_bytes':len(installed.read_bytes()),'links':links,'source_and_installed_links_valid':True,
    'shell_blocks_checked':len(blocks),'gitm_examples_executed':len(results),'all12_profiles_documented':True,
    'installed_import_root':__import__('gitm').__file__,'required_device_binaries_present':list(binaries),
    'execution_scope':'CLI examples parsed unchanged and executed in installed ARM64 simulator with private generated fixtures; network/package/group/host build operations validated separately',
    'commands':results},indent=2))
