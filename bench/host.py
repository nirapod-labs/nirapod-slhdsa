# SPDX-FileCopyrightText: nirapod-slhdsa contributors
# SPDX-License-Identifier: Apache-2.0
#
# bench/host.py
# =============
#
# The description of the measuring machine that bench/run.py records: CPU
# model, cores, memory, operating system, kernel, virtualisation, frequency
# policy and priority. Nothing here names the host or a user.
#
# CPU model on Linux AArch64. The arm64 kernel prints no model name in
# /proc/cpuinfo. Each processor block carries the fields of its Main ID
# Register (MIDR_EL1) instead: "CPU implementer" (bits 31:24), "CPU
# variant" (23:20), "CPU part" (15:4) and "CPU revision" (3:0), and
# /sys/devices/system/cpu/cpu0/regs/identification/midr_el1 holds the
# whole register where the kernel exposes it. The model is named from the
# implementer and part codes for the cores listed in ARM_CORES (the
# codes of the Arm Architecture Reference Manual and the cores' technical
# reference manuals, as also listed in the Linux kernel's
# arch/arm64/include/asm/cputype.h). An unlisted core is printed by its
# raw codes, for example "implementer 0x61 (Apple), part 0x048", never as
# "unknown". A machine with several core types lists each with its count.

import os
import platform
import shutil
import subprocess

IMPLEMENTERS = {0x41: "Arm", 0x42: "Broadcom", 0x43: "Cavium", 0x46: "Fujitsu",
                0x48: "HiSilicon", 0x4E: "NVIDIA", 0x50: "Applied Micro", 0x51: "Qualcomm",
                0x61: "Apple", 0x6D: "Microsoft", 0xC0: "Ampere"}

ARM_CORES = {
    (0x41, 0xD03): "Arm Cortex-A53", (0x41, 0xD04): "Arm Cortex-A35",
    (0x41, 0xD05): "Arm Cortex-A55", (0x41, 0xD07): "Arm Cortex-A57",
    (0x41, 0xD08): "Arm Cortex-A72", (0x41, 0xD09): "Arm Cortex-A73",
    (0x41, 0xD0A): "Arm Cortex-A75", (0x41, 0xD0B): "Arm Cortex-A76",
    (0x41, 0xD0C): "Arm Neoverse N1", (0x41, 0xD0D): "Arm Cortex-A77",
    (0x41, 0xD40): "Arm Neoverse V1", (0x41, 0xD41): "Arm Cortex-A78",
    (0x41, 0xD44): "Arm Cortex-X1", (0x41, 0xD46): "Arm Cortex-A510",
    (0x41, 0xD47): "Arm Cortex-A710", (0x41, 0xD48): "Arm Cortex-X2",
    (0x41, 0xD49): "Arm Neoverse N2", (0x41, 0xD4D): "Arm Cortex-A715",
    (0x41, 0xD4E): "Arm Cortex-X3", (0x41, 0xD4F): "Arm Neoverse V2",
    (0x41, 0xD80): "Arm Cortex-A520", (0x41, 0xD81): "Arm Cortex-A720",
    (0x41, 0xD82): "Arm Cortex-X4", (0x41, 0xD84): "Arm Neoverse V3",
    (0x41, 0xD8E): "Arm Neoverse N3",
    (0x61, 0x022): "Apple M1 (Icestorm)", (0x61, 0x023): "Apple M1 (Firestorm)",
    (0x61, 0x032): "Apple M2 (Blizzard)", (0x61, 0x033): "Apple M2 (Avalanche)",
    (0xC0, 0xAC3): "AmpereOne",
}


def out(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, errors="replace")
    except OSError:
        return ""
    return p.stdout.strip() if p.returncode == 0 else ""


def read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ""


def num(text):
    """A cpuinfo number: hexadecimal with 0x, otherwise decimal."""
    text = text.strip().lower()
    return int(text, 16) if text.startswith("0x") else int(text, 10)


def low_power_mode(pmset):
    """True when `pmset -g` reports lowpowermode 1."""
    return any(line.split()[:2] == ["lowpowermode", "1"] for line in pmset.splitlines())


def midr_fields(midr):
    """The MIDR_EL1 fields of a register value (int)."""
    return dict(implementer=(midr >> 24) & 0xFF, variant=(midr >> 20) & 0xF,
                part=(midr >> 4) & 0xFFF, revision=midr & 0xF)


def core_name(implementer, part):
    name = ARM_CORES.get((implementer, part))
    if name:
        return name
    who = IMPLEMENTERS.get(implementer)
    return f"implementer 0x{implementer:02x}{f' ({who})' if who else ''}, part 0x{part:03x}"


def aarch64_cpu(cpuinfo, midr_text=""):
    """(model, ids) from arm64 /proc/cpuinfo text and the cpu0 midr_el1 text.

    ids lists each distinct core type with its MIDR fields and count."""
    cores, block = [], {}
    for line in cpuinfo.splitlines() + [""]:
        if not line.strip():
            if "CPU implementer" in block and "CPU part" in block:
                cores.append((num(block["CPU implementer"]), num(block["CPU part"]),
                              num(block.get("CPU variant", "0")),
                              num(block.get("CPU revision", "0"))))
            block = {}
        elif ":" in line:
            k, v = line.split(":", 1)
            block[k.strip()] = v.strip()
    if not cores and midr_text:
        f = midr_fields(int(midr_text, 16))
        cores = [(f["implementer"], f["part"], f["variant"], f["revision"])]
    if not cores:
        return "MIDR not readable (no CPU implementer or part in /proc/cpuinfo)", []
    kinds = {}
    for c in cores:
        kinds[c] = kinds.get(c, 0) + 1
    ids = [dict(implementer=f"0x{i:02x}", part=f"0x{p:03x}", variant=f"0x{v:x}",
                revision=r, count=n, name=core_name(i, p))
           for (i, p, v, r), n in sorted(kinds.items())]
    if midr_text:
        ids[0]["midr_el1_cpu0"] = midr_text
    if len(ids) == 1:
        return ids[0]["name"], ids
    return " + ".join(f"{d['name']} x{d['count']}" for d in ids), ids


def linux_frequency(cpu):
    """Governor and boost state of the CPU the benchmark uses (cpu0 if unpinned)."""
    base = "/sys/devices/system/cpu"
    policy = f"{base}/cpu{cpu if cpu is not None else 0}/cpufreq"
    boost = (read(f"{policy}/boost") and f"policy boost={read(f'{policy}/boost')}") \
        or (read(f"{base}/cpufreq/boost") and f"boost={read(f'{base}/cpufreq/boost')}") \
        or (read(f"{base}/intel_pstate/no_turbo")
            and f"intel_pstate no_turbo={read(f'{base}/intel_pstate/no_turbo')}") \
        or "unavailable"
    freq = dict(governor=read(f"{policy}/scaling_governor") or "unavailable", boost=boost)
    driver = read(f"{policy}/scaling_driver")
    if driver:
        freq["driver"] = driver
    amd = read(f"{base}/amd_pstate/status")
    if amd:
        freq["amd_pstate"] = amd
    return freq


def linux_virtualisation(flags):
    virt = out(["systemd-detect-virt"]) if shutil.which("systemd-detect-virt") else ""
    if virt in ("none", ""):
        virt = ""
    if "microsoft" in read("/proc/sys/kernel/osrelease").lower():
        return "WSL2 (Hyper-V guest)"
    if not virt:
        virt = "hypervisor (cpuinfo flag)" if " hypervisor" in f" {flags}" else "none detected"
    return virt


def describe(arch, cpu):
    """The environment dict of the record; cpu is the --cpu value or None."""
    env = dict(machine=platform.machine(), arch=arch, system=platform.system(),
               kernel=platform.release(), cpus=os.cpu_count(), loadavg_start=os.getloadavg(),
               niceness=os.nice(0))
    if env["system"] == "Darwin":
        def sysctl(k):
            return out(["sysctl", "-n", k])
        env.update(os=f"macOS {out(['sw_vers', '-productVersion'])}",
                   cpu=sysctl("machdep.cpu.brand_string") or "not reported by sysctl",
                   perf_cores=sysctl("hw.perflevel0.physicalcpu"),
                   efficiency_cores=sysctl("hw.perflevel1.physicalcpu"),
                   memory_bytes=int(sysctl("hw.memsize") or 0),
                   virtualisation="virtual machine" if sysctl("kern.hv_vmm_present") == "1"
                   else "none (native)",
                   frequency="not controllable on macOS; dynamic voltage and frequency scaling",
                   low_power_mode=low_power_mode(out(["pmset", "-g"])),
                   thermal=out(["pmset", "-g", "therm"]).replace("\n", "; ") or "unavailable")
    elif env["system"] == "Linux":
        info = read("/proc/cpuinfo")
        model = [line.split(":", 1)[1].strip() for line in info.splitlines()
                 if line.startswith("model name")]
        flags = " ".join(line for line in info.splitlines() if line.startswith("flags"))
        if arch == "aarch64":
            midr = read("/sys/devices/system/cpu/cpu0/regs/identification/midr_el1")
            env["cpu"], env["cpu_ids"] = aarch64_cpu(info, midr)
        else:
            env["cpu"] = model[0] if model else "no model name in /proc/cpuinfo"
        osr = dict(line.split("=", 1) for line in read("/etc/os-release").splitlines()
                   if "=" in line)
        mem = [line.split()[1] for line in read("/proc/meminfo").splitlines()
               if line.startswith("MemTotal")]
        env.update(os=osr.get("PRETTY_NAME", "Linux").strip('"'),
                   memory_bytes=int(mem[0]) * 1024 if mem else 0,
                   virtualisation=linux_virtualisation(flags),
                   frequency=linux_frequency(cpu))
    else:
        raise ValueError(f"unsupported system {env['system']}")
    return env
