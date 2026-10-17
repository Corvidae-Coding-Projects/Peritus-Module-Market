#!/usr/bin/env python3
"""Build one native Rust module and print its canonical Peritus package digest.

Run from this workspace, for example: python3 scripts/package.py deep-research
No install hook or build runs when an end user installs the resulting package.
"""
import argparse,hashlib,json,os,shutil,subprocess,tomllib
from pathlib import Path
ap=argparse.ArgumentParser();ap.add_argument('module');ap.add_argument('--target');ap.add_argument('--skip-build',action='store_true');a=ap.parse_args()
root=Path(__file__).resolve().parents[1];folder=(root/'modules'/a.module).resolve()
if folder.parent!=root/'modules':raise SystemExit('module must name a direct modules child')
m=tomllib.loads((folder/'module.toml').read_text());cargo=tomllib.loads((folder/'Cargo.toml').read_text());name=cargo['package']['name']
triple=a.target or next(l.split(': ',1)[1]for l in subprocess.check_output(['rustc','-vV'],text=True).splitlines()if l.startswith('host: '))
if triple not in m['code']['artifacts']:raise SystemExit('declare this target in module.toml [code.artifacts] before packaging it')
if not a.skip_build:subprocess.run(['cargo','build','--locked','--release','--jobs','2','-p',name,*(['--target',a.target]if a.target else[])],cwd=root,check=True)
target=Path(os.environ.get('CARGO_TARGET_DIR',root/'target'));artifact=target.joinpath(*([a.target] if a.target else []),'release',name+('.exe'if 'windows'in triple else ''))
destination=folder/m['code']['artifacts'][triple];destination.parent.mkdir(parents=True,exist_ok=True);shutil.copyfile(artifact,destination);destination.chmod(0o755)
canonical={key:m[key]for key in ['schema','id','version','name','description']};canonical.update(roles=m.get('roles',[]),stages=m.get('stages',[]),resources=m.get('resources',[]))
canonical['code']={key:m['code'][key]for key in ['abi','artifacts','tools']};canonical['code']['artifacts']=dict(sorted(canonical['code']['artifacts'].items()))
h=hashlib.sha256(b'peritus-module-v1\0'+json.dumps(canonical,ensure_ascii=False,separators=(',',':')).encode())
for relative in sorted(canonical['resources']):
 path=folder/relative
 if path.resolve().is_relative_to(folder) is False or any(p.is_symlink()for p in [path,*list(path.parents)[:len(Path(relative).parts)-1]]):raise SystemExit('resources must be regular files under this package')
 data=path.read_bytes();encoded=relative.encode();h.update(len(encoded).to_bytes(8,'big'));h.update(encoded);h.update(len(data).to_bytes(8,'big'));h.update(data)
print(json.dumps({'id':m['id'],'version':m['version'],'target':triple,'digest':h.hexdigest(),'binary':str(destination)},indent=2))
