"""Bounded numeric telemetry for a disposable diagnostic scanner only.

No file content, directory entries, paths or arbitrary scanner text are emitted.
Measurements are snapshots and do not prove exclusive cause of shared-FS growth.
"""
import os
from pathlib import Path
import shutil
import stat
import threading

MAX_ENTRIES = 16
MAX_SAMPLES = 720


def directory_fd(path):
    fd=os.open('/',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:
        for part in Path(path).absolute().parts[1:]:
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child
        return fd
    except BaseException:
        os.close(fd)
        raise


def file_counts(fd, name):
    try:st=os.stat(name,dir_fd=fd,follow_symlinks=False)
    except FileNotFoundError:return 0,0,False
    if not stat.S_ISREG(st.st_mode):return 0,0,True
    if st.st_size<0 or st.st_blocks<0:return 0,0,True
    return st.st_size,st.st_blocks*512,False


def cache_file(cache, directory, name):
    try:
        root=directory_fd(cache)
    except FileNotFoundError:return 0,0,False
    try:
        try:child=os.open(directory,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root)
        except FileNotFoundError:return 0,0,False
        except OSError:return 0,0,True
        try:return file_counts(child,name)
        finally:os.close(child)
    finally:os.close(root)


def export_counts(scratch):
    """Inspect at most 16 process dirs, and 16 entries per dir, without links."""
    logical=allocated=0;partial=False
    root=directory_fd(scratch)
    try:
        with os.scandir(root) as dirs:
            for index,entry in enumerate(dirs):
                if index>=MAX_ENTRIES:partial=True;break
                if not entry.name.startswith('trivy-'):continue
                try:child=os.open(entry.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=root)
                except OSError:partial=True;continue
                try:
                    with os.scandir(child) as files:
                        for inner,file in enumerate(files):
                            if inner>=MAX_ENTRIES:partial=True;break
                            if not file.name.startswith('docker-export-'):continue
                            a,b,missing=file_counts(child,file.name)
                            logical+=a;allocated+=b;partial |= missing
                finally:os.close(child)
    finally:os.close(root)
    return logical,allocated,partial


def measure(scratch,cache,output,docker_root,initial):
    exp_l,exp_a,partial=export_counts(scratch)
    db_l,db_a,db_partial=cache_file(cache,'db','trivy.db')
    fan_l,fan_a,fan_partial=cache_file(cache,'fanal','fanal.db')
    return {'export_logical_bytes':exp_l,'export_allocated_bytes':exp_a,
            'db_logical_bytes':db_l,'db_allocated_bytes':db_a,
            'fanal_logical_bytes':fan_l,'fanal_allocated_bytes':fan_a,
            'output_free_decrease_bytes':max(0,initial['output_free']-shutil.disk_usage(output).free),
            'docker_free_decrease_bytes':max(0,initial['docker_free']-shutil.disk_usage(docker_root).free),
            'partial':bool(partial or db_partial or fan_partial)}


class Sampler:
    def __init__(self,scratch,cache,output,docker_root,initial,interval=0.5):
        self.args=(scratch,cache,output,docker_root,initial)
        self.interval=interval;self.event=threading.Event();self.thread=None;self.finished=None
        self.result={'status':'unavailable','samples':0,'partial_samples':0,
                     'sample_errors':0,'peaks':{}}

    def run(self):
        while not self.event.is_set() and self.result['samples']<MAX_SAMPLES:
            try:
                data=measure(*self.args);self.result['samples']+=1
                self.result['partial_samples']+=int(data.pop('partial'))
                for key,value in data.items():
                    self.result['peaks'][key]=max(self.result['peaks'].get(key,0),value)
            except (OSError,ValueError):self.result['sample_errors']+=1
            self.event.wait(self.interval)
        self.result['status']='sampled' if self.result['samples'] else 'unavailable'

    def start(self):
        self.thread=threading.Thread(target=self.run,daemon=True);self.thread.start()

    def stop(self):
        self.event.set()
        if self.thread is not None:self.thread.join(timeout=2)
        stopped=self.thread is None or not self.thread.is_alive()
        if not stopped:return {'status':'sampler-unquiesced','samples':0,'partial_samples':0,'sample_errors':0,'peaks':{}}
        return dict(self.result)
