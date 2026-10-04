#!/usr/bin/env python3
"""Read-only ordinary-resource sampler.

Run inside the already selected Apple Container guest. It reads an existing test
cluster workspace and emits one JSON object to stdout; it creates no files,
opens no namespaces, and performs no lifecycle operation.
"""
import argparse, json, os, pathlib, re, stat, sys, time

class SnapshotError(RuntimeError): pass

def read(path, binary=False):
    try:
        return pathlib.Path(path).read_bytes() if binary else pathlib.Path(path).read_text()
    except OSError as e: raise SnapshotError(f"read {path}: {e}")

def root_regular(path):
    s=os.stat(path, follow_symlinks=False)
    if not stat.S_ISREG(s.st_mode) or s.st_uid != 0 or (stat.S_IMODE(s.st_mode)&0o022):
        raise SnapshotError(f"unsafe receipt {path}")

def pid_number(text, name):
    if not re.fullmatch(r"[1-9][0-9]*", text.strip()) or int(text) <= 1: raise SnapshotError(f"invalid {name}")
    return int(text)

def proc_stat(pid):
    line=read(f"/proc/{pid}/stat").strip()
    try: rest=line.rsplit(") ",1)[1].split()
    except IndexError: raise SnapshotError(f"malformed /proc/{pid}/stat")
    if len(rest)<20: raise SnapshotError(f"short /proc/{pid}/stat")
    # Linux fields: state=3, utime=14, stime=15, starttime=22.
    return {"state":rest[0], "utime_ticks":int(rest[11]), "stime_ticks":int(rest[12]), "starttime_ticks":int(rest[19])}

def cgroup_for_pid(pid):
    rows=read(f"/proc/{pid}/cgroup").splitlines()
    matches=[r.split(":",2)[2] for r in rows if r.startswith("0::")]
    if len(matches)!=1: raise SnapshotError(f"no unified cgroup for pid {pid}")
    return matches[0]

def cgroup_relative(path):
    prefix="/sys/fs/cgroup/"
    if not path.startswith(prefix) or "/../" in path or path.endswith("/.."): raise SnapshotError(f"unsafe cgroup {path}")
    return "/"+path[len(prefix):]

def cgroup_files(path):
    out={}
    for name in ("cpu.stat","memory.current","memory.peak","io.stat","cgroup.procs"):
        try:
            out[name]=read(f"{path}/{name}").strip().splitlines()
        except SnapshotError as e:
            # Controller availability is kernel/configuration dependent.  It is
            # an observation gap, not evidence that the bound cgroup is unsafe.
            out[name]={"status":"unavailable","reason":str(e)}
    return out

def process_snapshot(pid, expected_cgroup=None):
    actual=cgroup_for_pid(pid)
    if expected_cgroup is not None and actual != expected_cgroup and not actual.startswith(expected_cgroup.rstrip("/")+"/"):
        raise SnapshotError(f"pid {pid} cgroup {actual} outside {expected_cgroup}")
    out={"pid":pid,"cgroup":actual}
    try:
        out["raw_cpu"]=proc_stat(pid)
        status=read(f"/proc/{pid}/status")
        rss=[x.split()[1] for x in status.splitlines() if x.startswith("VmRSS:")]
        if len(rss)==1: out["rss_kib"]=int(rss[0])
        else: out["rss_kib"]={"status":"unavailable","reason":"VmRSS absent"}
        io={}
        for line in read(f"/proc/{pid}/io").splitlines():
            if ":" in line:
                k,v=line.split(":",1); io[k]=int(v.strip())
        out["io"]=io if "read_bytes" in io and "write_bytes" in io else {"status":"unavailable","reason":"read/write bytes absent"}
        out["fd_count"]=len(os.listdir(f"/proc/{pid}/fd"))
        out["task_count"]=len(os.listdir(f"/proc/{pid}/task"))
    except (SnapshotError,OSError,ValueError) as e:
        out["process_metrics"]={"status":"unavailable","reason":str(e)}
    return out


def cgroup_tree(root):
    root=pathlib.Path(root); host_root=str(root).startswith('/sys/fs/cgroup/')
    if not root.is_dir() or root.is_symlink(): raise SnapshotError(f"unsafe cgroup root {root}")
    rows=[]; seen=set()
    for base,dirs,_ in os.walk(root, followlinks=False):
        if len(rows)>=128: raise SnapshotError("owned cgroup tree exceeds bound")
        basep=pathlib.Path(base)
        dirs[:]=[d for d in dirs if not (basep/d).is_symlink()]
        rel="/"+str(basep.relative_to('/sys/fs/cgroup')) if host_root else None
        pids=[]
        for text in read(basep/'cgroup.procs').split():
            pid=pid_number(text,"cgroup pid")
            if pid in seen: raise SnapshotError(f"task pid {pid} appears in multiple cgroups")
            seen.add(pid)
            # Inner machine cgroup views are read through /proc/<runtime>/root;
            # bind each task to its actual host unified cgroup rather than
            # pretending the namespace-relative path is host-global.
            # A cgroup mounted through a machine's mount namespace has paths
            # relative to that namespace.  The host /proc cgroup path cannot
            # safely be compared with it; retain the actual host path instead.
            try:
                pids.append(process_snapshot(pid,rel))
            except SnapshotError as e:
                # A task can exit after cgroup.procs was read.  Preserve that
                # race as an unavailable process observation rather than
                # turning a resource sample into a traffic failure.
                pids.append({"pid":pid,"status":"unavailable","reason":str(e)})
        rows.append({"cgroup":rel,"observed_path":str(basep),"raw":cgroup_files(str(basep)),"tasks":pids})
    return rows

def application_report_binding(path):
    if path is None: return {"status":"unbound: no applicationReport text supplied"}
    try: text=read(path)
    except SnapshotError as e: return {"status":"unavailable: applicationReport unreadable","reason":str(e)}
    names=re.findall(r"(?m)^Application: ([^\n]+)$",text)
    uuids=re.findall(r"(?m)^\s*containerRuntime: .* uuid=([0-9]+)$",text)
    if len(names)!=1 or not uuids or len(set(uuids))!=len(uuids):
        return {"status":"unavailable: applicationReport stringify binding is incomplete"}
    return {"application_name":names[0],"container_uuid_decimal":sorted(uuids,key=int),"report_path":path,
            "per_process_uuid_attribution":"unavailable: report has application runtime UUIDs but no cgroup PID mapping"}

def application_cgroups(machine_pid, binding):
    root=pathlib.Path(f"/proc/{machine_pid}/root/sys/fs/cgroup/containers.slice")
    if not root.exists(): return []
    if root.is_symlink() or not root.is_dir(): raise SnapshotError("unsafe application cgroup root")
    # Neuron assigns container.name from decimal plan.uuid; application names are
    # not cgroup names. ApplicationStatusReport exposes only runtime UUIDs.
    wanted=set(binding.get("container_uuid_decimal",[]))
    out=[]
    ignored=[]
    for child in root.iterdir():
        if child.is_symlink(): raise SnapshotError("symlink in application cgroup root")
        if not child.is_dir():
            # cgroup v2 pseudo-files (cgroup.*, cpu.*, memory.*, etc.) live
            # beside child cgroups and are not container names.
            continue
        if not child.name.endswith('.slice'):
            ignored.append(child.name)
            continue
        container_name=child.name[:-6]
        if not re.fullmatch(r"[1-9][0-9]*",container_name): raise SnapshotError("non-canonical container cgroup name")
        leaf=child/'leaf'
        if leaf.is_symlink() or not leaf.is_dir(): raise SnapshotError("missing application cgroup leaf")
        row={"container_name":container_name,"machine_supervisor_pid":machine_pid,"cgroup_tree":cgroup_tree(leaf),
             "container_rootfs_path":f"/containers/{container_name}/rootfs",
             "container_storage_payload_path":f"/containers/storage/{container_name}/data"}
        if container_name in wanted:
            row["application_report"]=binding
        else:
            row["application_report"]={"status":"unbound: canonical container name not in supplied application report"}
        out.append(row)
    return {"containers":out,"unrecognized_child_cgroups":ignored,
            "bound_report_runtime_count":sum(r["container_name"] in wanted for r in out)}

def provider_binding(workspace, cgroup_root):
    root_regular(f"{workspace}/virtual-datacenter.pid")
    root_regular(f"{workspace}/virtual-datacenter.identity")
    pid=pid_number(read(f"{workspace}/virtual-datacenter.pid"),"provider pid")
    runtime=pid_number(read(f"{workspace}/virtual-datacenter.identity"),"runtime identity")
    argv=read(f"/proc/{pid}/cmdline",binary=True).split(b"\0")[:-1]
    if len(argv)<4 or pathlib.Path(argv[0].decode()).name!="bash" or not re.fullmatch(rb"/proc/self/fd/[0-9]+",argv[1]) or argv[2] not in (b"--serve",b"--serve-adopt"):
        raise SnapshotError("provider cmdline ownership mismatch")
    if (argv[2]==b"--serve" and argv[3].decode()!=workspace) or (argv[2]==b"--serve-adopt" and (len(argv)<6 or argv[5].decode()!=workspace)):
        raise SnapshotError("provider workspace ownership mismatch")
    expected=cgroup_relative(cgroup_root)+"/provider"
    return runtime, process_snapshot(pid,expected)

def inactive_pair_observation(pair_root):
    # This is a provider directory count only. It cannot prove registry-level
    # admission, retirement, or migration records, so callers must retain gap.
    try: entries=list(pathlib.Path(pair_root).iterdir())
    except FileNotFoundError: entries=[]
    except OSError as e:
        return {"status":"unavailable: pair root unreadable","reason":str(e),
                "registry_admission_retirement_counts":"unobservable: no generic read-only registry/report contract"}
    pairs=[]
    for p in entries:
        if not p.is_dir() or p.is_symlink(): raise SnapshotError(f"unexpected pair-root entry {p}")
        pairs.append(p.name)
    provider_processes=0
    for d in pathlib.Path("/proc").iterdir():
        if not d.name.isdigit(): continue
        try: argv=(d/"cmdline").read_bytes().split(b"\0")[:-1]
        except FileNotFoundError: continue
        except OSError:
            # An unrelated process may leave while /proc is traversed.
            continue
        if b"--pair-serve" in argv or b"--pair-recover-remove" in argv: provider_processes+=1
    return {"pair_directory_names":sorted(pairs),"provider_process_count":provider_processes,
            "registry_admission_retirement_counts":"unobservable: no generic read-only registry/report contract"}

def snapshot(workspace, pair_root, application_report):
    workspace=os.path.realpath(workspace)
    if not workspace.startswith("/") or workspace == "/" or workspace.endswith("/"):
        raise SnapshotError("workspace must be canonical non-root absolute path")
    root_regular(f"{workspace}/test-cluster-manifest.json")
    root_regular(f"{workspace}/virtual-datacenter.cgroup")
    root_regular(f"{workspace}/virtual-datacenter.runtime")
    manifest=json.loads(read(f"{workspace}/test-cluster-manifest.json"))
    if manifest.get("workspaceRoot")!=workspace or not isinstance(manifest.get("nodes"),list): raise SnapshotError("manifest workspace/nodes mismatch")
    cgroup_root=read(f"{workspace}/virtual-datacenter.cgroup").strip()
    runtime, provider=provider_binding(workspace,cgroup_root)
    runtime_lines=read(f"{workspace}/virtual-datacenter.runtime").strip().splitlines()
    if len(runtime_lines)!=len(manifest["nodes"]): raise SnapshotError("runtime/manifest node count mismatch")
    binding=application_report_binding(application_report)
    machines=[]
    for index,(node,pid_text) in enumerate(zip(manifest["nodes"],runtime_lines),1):
        if node.get("index")!=index or node.get("namespace")!=f"pvd-m{index}-{runtime}": raise SnapshotError("manifest runtime identity mismatch")
        pid=pid_number(pid_text,"machine pid")
        machines.append({"index":index,"runtime_roles":["machine-supervisor",node.get("role")],
                         "switchboard_role":"not separately attributable from manifest; never double-count this PID",
                         "process":process_snapshot(pid,cgroup_relative(cgroup_root)+f"/machine{index}"),
                         "cgroup_tree":cgroup_tree(f"{cgroup_root}/machine{index}"),
                         "application_cgroups":application_cgroups(pid,binding)})
    return {"schema":1,"monotonic_ns":time.monotonic_ns(),"workspace":workspace,"runtime_identity":runtime,
            "provider":{"process":provider,"cgroup_tree":cgroup_tree(f"{cgroup_root}/provider")},"machines":machines,
            "container_filesystem_allocated_bytes":"unobservable: provider exposes Btrfs machine roots but no persisted qgroup-to-container attribution; do not use statvfs, image length, or du as allocated container bytes",
            "cgroup_disk_usage":"unobservable: cgroup v2 exposes no disk-usage counter; do not substitute workspace/image size",
            "inactive_migration":inactive_pair_observation(pair_root)}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--workspace",required=True); ap.add_argument("--pair-root",default="/mnt/prodigy-vdc-pairs"); ap.add_argument("--application-report")
    args=ap.parse_args()
    try: print(json.dumps(snapshot(args.workspace,args.pair_root,args.application_report),sort_keys=True,separators=(",",":")))
    except (SnapshotError,json.JSONDecodeError,ValueError) as e:
        print(f"resource-snapshot: {e}",file=sys.stderr); return 1
    return 0
if __name__=="__main__": raise SystemExit(main())
