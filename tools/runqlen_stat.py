from __future__ import print_function
from bcc import BPF, PerfType, PerfSWConfig, utils
from time import sleep, strftime
from tempfile import NamedTemporaryFile
from os import open, close, dup, unlink, O_WRONLY
import argparse

countdown = 1000
debug = 0
frequency = 999

def check_runnable_weight_field():
    # Define the bpf program for checking purpose
    bpf_check_text = """
#include <linux/sched.h>
unsigned long dummy(struct sched_entity *entity)
{
    return entity->runnable_weight;
}
"""

    # Get a temporary file name
    tmp_file = NamedTemporaryFile(delete=False)
    tmp_file.close();

    # Duplicate and close stderr (fd = 2)
    old_stderr = dup(2)
    close(2)

    # Open a new file, should get fd number 2
    # This will avoid printing llvm errors on the screen
    fd = open(tmp_file.name, O_WRONLY)
    try:
        t = BPF(text=bpf_check_text)
        success_compile = True
    except:
        success_compile = False

    # Release the fd 2, and next dup should restore old stderr
    close(fd)
    dup(old_stderr)
    close(old_stderr)

    # remove the temporary file and return
    unlink(tmp_file.name)
    return success_compile


# define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/kernel.h>

// Declare enough of cfs_rq to find nr_running, since we can't #import the
// header. This will need maintenance. It is from kernel/sched/sched.h:
struct cfs_rq_partial {
    struct load_weight load;
    RUNNABLE_WEIGHT_FIELD
    unsigned int nr_running, h_nr_running;
};

typedef struct cpu_key {
    int cpu;
    unsigned int slot;
} cpu_key_t;
BPF_HISTOGRAM(dist, cpu_key_t, MAX_CPUS);

int do_perf_event()
{
    unsigned int len = 0;
    pid_t pid = 0;
    struct task_struct *task = NULL;
    struct cfs_rq_partial *my_q = NULL;

    // Fetch the run queue length from task->se.cfs_rq->nr_running. This is an
    // unstable interface and may need maintenance. Perhaps a future version
    // of BPF will support task_rq(p) or something similar as a more reliable
    // interface.
    task = (struct task_struct *)bpf_get_current_task();
    my_q = (struct cfs_rq_partial *)task->se.cfs_rq;
    len = my_q->nr_running;

    cpu_key_t key = {.slot = len}; 
    key.cpu = bpf_get_smp_processor_id(); 
    dist.increment(key);

    return 0;
}
"""

if check_runnable_weight_field():
    bpf_text = bpf_text.replace('RUNNABLE_WEIGHT_FIELD', 'unsigned long runnable_weight;')
else:
    bpf_text = bpf_text.replace('RUNNABLE_WEIGHT_FIELD', '')

num_cpus = len(utils.get_online_cpus())

# initialize BPF & perf_events
b = BPF(text=bpf_text, cflags=['-DMAX_CPUS=%s' % str(num_cpus)])
b.attach_perf_event(ev_type=PerfType.SOFTWARE,
    ev_config=PerfSWConfig.CPU_CLOCK, fn_name="do_perf_event",
    sample_period=0, sample_freq=frequency, cpu = 0)

dist = b.get_table("dist")

while (1):
    sleep(0.01)
    print("---------------------------------")
    dist.print_linear_hist("runqlen", "cpu")

    dist.clear()

    countdown -= 1
    if countdown == 0:
        exit()
