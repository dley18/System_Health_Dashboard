from typing import List, Optional, Literal, Dict, Tuple
from datetime import datetime

from pydantic import BaseModel, Field


# Common helpers
# Severity across logs, alerts, and security findings
Severity = Literal["info", "warning", "error", "critical"]
# High-level state for OS services/daemons
ServiceState = Literal["running", "stopped", "paused", "failed", "unknown"]
# System firewall overall status
FirewallState = Literal["enabled", "disabled", "unknown"]
# Anti-virus/endpoint protection
AVState = Literal["healthy", "out_of_date", "disabled", "unknown"]
# OS family for platform-specific logic
OSType = Literal["windows", "linux", "macos", "bsd", "unknown"]
# Interface classification for UI grouping
IFaceType = Literal["ethernet", "wifi", "loopback", "virtual", "cellular", "unknown"]
# Socket/probe protocol
Protocol = Literal["tcp", "udp", "icmp", "other"]
# File system family for paritions
FilesystemType = Literal["ntfs", "fat32", "exfat", "ext4", "xfs", "apfs", "btrfs", "zfs", "other"]

class Percent(BaseModel):
    """Represents a percentage contrained to 0-100."""
    value: float = Field(ge=0.0, le=100.0, description="Percentage in [0,100].")


# CPU

class CPUCoreUsage(BaseModel):
    """Per-logical-core usage snapshot."""

    core_index: int = Field(ge=0) 
    """Core logical index (0-based)."""

    usage_pct: float = Field(ge=0.0, le=100.0)
    """% of that core's time not idle"""

class CPUFrequency(BaseModel):
    """Instantaneous and capability clock speeds."""

    current_mhz: Optional[float] = Field(default=None, ge=0.0)
    """MHz; may be averaged across cores."""

    min_mhz: Optional[float] = Field(default=None, ge=0.0)
    """Minimum non-idle clock."""

    max_mhz: Optional[float] = Field(default=None, ge=0.0)
    """Maximum non-turbo base clock."""

    turbo_mhz: Optional[float] = Field(default=None, ge=0.0)
    """Advertised turbo boost ceiling if known."""

class CPUTemperature(BaseModel):
    """Thermal data for CPU package and cores."""
    package_c: Optional[float] = None
    """°C; overall package sensor."""

    per_core_c: Optional[List[Optional[float]]] = None
    """°C per logical core; `None` where unavailable."""

    hotspot_c: Optional[float] = None
    """°C; highest sensor reading if exposed."""

class CPUThrottleStatus(BaseModel):
    """Whether the CPU is throttling and why."""

    is_throttling: bool
    """True if frequency is constrained below requested due to a limiter."""

    reason: Optional[Literal["thermal", "power", "current", "other"]] = None
    """Dominant cause when known."""

class CPUPower(BaseModel):
    """Package power telementary."""

    watts: Optional[float] = Field(default=None, ge=0.0)
    """W; estimated or reported package power."""

    voltage_v: Optional[float] = Field(default=None, ge=0.0)
    """V; supply voltage if available."""

class CPULoadAverages(BaseModel):
    """Lunix-style moving averages of runnable tasks."""

    over_1m: Optional[float] = Field(default=None, ge=0.0)
    over_5m: Optional[float] = Field(default=None, ge=0.0)
    over_15m: Optional[float] = Field(default=None, ge=0.0)
    """runnable tasks; meaningful mainly on unix"""

class TopCPUProcess(BaseModel):
    """Top consumer rows for the Proccesses table."""

    pid: int
    """OS process ID."""

    name: str
    """Process executable/name."""

    cpu_pct: float = Field(ge=0.0, le=100.0)
    """% of one CPU by convention; may sum over 100% on multi-core systems."""

    user_time_s: Optional[float] = Field(default=None, ge=0.0)
    """Cumulative CPU seconds since start or last sample."""

    system_time_s: Optional[float] = Field(default=None, ge=0.0)
    """Cumulative CPU seconds since start or last sample."""

class CPUModel(BaseModel):
    """Aggregate CPU panel."""

    timestamp: datetime = Field(default_factory=datetime.now)
    """Collection time."""

    sample_interval_s: Optional[float] = Field(default=None, ge=0.0)
    """Seconds representing the sampling window."""

    physical_cores: Optional[int] = Field(default=None, ge=1)
    """CPU physical core count."""

    locial_cores: Optional[int] = Field(default=None, ge=1)
    """CPU logical core count."""

    usage_total_pct: float = Field(ge=0.0, le=100.0)
    """% across all cores."""

    per_core: Optional[List[CPUCoreUsage]] = None
    """Detail per logical core."""

    frequency: Optional[CPUFrequency] = None
    """Helpful for diagnosing driver or contention issues."""

    temperature: Optional[CPUTemperature] = None
    """Helpful for diagnosing driver or contention issues."""

    throttle: Optional[CPUThrottleStatus] = None
    """Helpful for diagnosing driver or contention issues."""

    power: Optional[CPUPower] = None
    """Helpful for diagnosing driver or contention issues."""

    load_avg: Optional[CPULoadAverages] = None
    """Helpful for diagnosing driver or contention issues."""

    context_switches_per_sec: Optional[float] = Field(default=None, ge=0.0)
    """Helpful for diagnosing driver or contention issues."""

    interrupts_per_sec: Optional[float] = Field(default=None, ge=0.0)
    """Helpful for diagnosing driver or contention issues."""

    top_processes: Optional[List[TopCPUProcess]] = None
    """Snapshot of heavy CPU users."""


# Memory (RAM)

class SwapStats(BaseModel):
    """Virtual memory backing store statistics."""

    total_bytes: int = Field(ge=0)
    """Total swap."""

    used_bytes: int = Field(ge=0)
    """Toatal used."""

    usage_pct: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    """Optional precomputed proportion."""

    swap_in_per_sec: Optional[float] = Field(default=None, ge=0.0)
    """Bytes in per second."""

    swap_out_per_sec: Optional[float] = Field(default=None, ge=0.0)
    """Bytes out per second."""


class PressureStatus(BaseModel):
    """Unified memory pressure indicator."""

    instant: Optional[Literal["normal", "elevated", "critical"]] = None
    """Discrete state for UI."""

    score: Optional[float] = Field(default=None, ge=0.0)
    """macOS memory pressure or Linux PSI percentage."""

class FaultStats(BaseModel):
    """Demand paging activity."""

    soft_per_sec: Optional[float] = Field(default=None, ge=0.0)
    """Minor fualts/s (no disk)."""

    hard_per_sec: Optional[float] = Field(default=None, ge=0.0)
    """Major faults/s (disk/ssd access)."""

class WindowsRAMExtras(BaseModel):
    """Platform specific breakdown (Optional)."""

    commit_bytes: Optional[float] = Field(default=None, ge=0.0)
    commit_limit_bytes: Optional[int] = Field(default=None, ge=0)
    paged_pool_bytes: Optional[int] = Field(default=None, ge=0)
    nonpaged_pool_bytes: Optional[int] = Field(default=None, ge=0)

class LinuxRAMExtras(BaseModel):
    """Platform specific breakdown (Optional)."""

    buffers_bytes: Optional[int] = Field(default=None, ge=0)
    slab_bytes: Optional[int] = Field(default=None, ge=0)
    psi_mem_some: Optional[float] = Field(default=None, ge=0.0)
    psi_mem_full: Optional[float] = Field(default=None, ge=0.0)
    thp_enabled: Optional[bool] = None
    zswap_in_use_bytes: Optional[int] = Field(default=None, ge=0)
    zram_in_use_bytes: Optional[int] = Field(default=None, ge=0)

class MacOSRAMExtras(BaseModel):
    """Platform specific breakdown (Optional)."""

    wired_bytes: Optional[int] = Field(default=None, ge=0)

class PlatformRAMExtras(BaseModel):
    """Platform specific breakdown (Optional)."""
    windows: Optional[WindowsRAMExtras] = None
    linux: Optional[LinuxRAMExtras] = None
    macos: Optional[MacOSRAMExtras] = None

class TopMemoryProcess(BaseModel):
    """Per-process memory heavy hitters."""

    pid: int
    """Process ID."""

    name: str
    """Process name."""

    rss_bytes: int = Field(ge=0)
    """Resident/working set size."""

    share_pct: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    """Share of total RAM."""

    hard_faults_per_sec: Optional[float] = Field(default=None, ge=0.0)
    """Paging pain indicator."""

class RAMModel(BaseModel):
    """Aggregate memory panel."""

    timestamp: datetime = Field(default_factory=datetime.now)
    """Collection time."""

    sample_interval_s: Optional[float] = Field(default=None, ge=0.0)
    """Seconds representing the sampling window."""

    total_bytes: int = Field(ge=0)
    """Physical RAM."""

    used_effective_bytes: int = Field(ge=0, description="Preferred: Total - Available.")
    """Prefer total - available"""

    available_bytes: int = Field(ge=0)
    """Reclaimable + truly free."""

    usage_pct: float = Field(ge=0.0, le=100.0)
    """Effective used / total."""

    cache_bytes: Optional[int] = Field(default=None, ge=0)
    """Breakdown component."""

    kernal_bytes: Optional[int] = Field(default=None, ge=0)
    """Breakdown component."""

    compressed_bytes: Optional[int] = Field(default=None, ge=0)
    """Breakdown component."""

    swap: Optional[SwapStats] = None
    """Swap."""

    pressure: Optional[PressureStatus] = None
    """Pressure."""

    faults: Optional[FaultStats] = None
    """Faults."""

    platform: Optional[PlatformRAMExtras] = None
    """Platform."""

    top_processes: Optional[List[TopMemoryProcess]] = None
    """Top processes."""

# Storage

class DiskPartition(BaseModel):
    """Logical volume/partition status."""

    device: str
    """Device path."""

    mount_point: str
    """Mount/letter."""

    fs_type: FilesystemType
    """Filesystem."""

    total_bytes: int = Field(ge=0)
    """Capacity metric."""

    used_bytes: int = Field(ge=0)
    """Capacity metric."""

    free_bytes: int = Field(ge=0)
    """Capacity metric."""

    usage_pct: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    """Convenience percent."""

    read_only: Optional[bool] = None
    """True if mounted RO or media is write-protected."""

class DiskIOStats(BaseModel):
    """Throughput and IOPS per device."""

    device: str
    """Identifier matches OS naming."""

    read_bytes_per_sec: Optional[float] = Field(default=None, ge=0.0)
    """Bytes/s ."""

    write_bytes_per_sec: Optional[float] = Field(default=None, ge=0.0)
    """Bytes/s ."""

    read_iops: Optional[float] = Field(default=None, ge=0.0)
    """IO operation/s ."""

    write_iops: Optional[float] = Field(default=None, ge=0.0)
    """IO operation/s ."""

    avg_read_ms: Optional[float] = Field(default=None, ge=0.0)
    """Average service time per IO (ms)."""

    avg_write_ms: Optional[float] = Field(default=None, ge=0.0)
    """Average service time per IO (ms)."""

class SmartAttribute(BaseModel):
    """SMART datum from storage device."""

    id: Optional[int] = None
    """Attribute ID."""

    name: str
    """Attribute name."""

    value: Optional[float] = None
    """Attribute value."""

    worst: Optional[float] = None
    """Attribute worst."""

    threshold: Optional[float] = None
    """Attribute threshold."""

    raw: Optional[str] = None
    """Attribute raw."""

    failed: Optional[bool] = None
    """Attribute failed."""

class DiskHealth(BaseModel):
    """Condensed health info per disk."""

    device: str
    """Physical device."""

    smart_overall_pass: Optional[bool] = None
    """SMART OK flag."""

    temperature_c: Optional[float] = None
    """Drive temperature."""

    attributes: Optional[List[SmartAttribute]] = None
    """Selected SMARTs."""

class StorageModel(BaseModel):
    """Aggregate storage model."""

    timestamp: datetime = Field(default_factory=datetime.now)
    """Colletion time."""

    partitions: List[DiskPartition]
    """Mounted volumes."""

    io: Optional[List[DiskIOStats]] = None
    """Live throughput."""

    health: Optional[List[DiskHealth]] = None
    """Disk device health."""

# Network

class AddressInfo(BaseModel):
    """Assigned addresses."""

    ipv4: Optional[str] = None
    """IPV4 address."""

    ipv6: Optional[str] = None
    """IPv6 address."""

    mac: Optional[str] = None
    """MAC address."""

class InterfaceCounters(BaseModel):
    """Rate metrics (per second)."""

    bytes_sent_per_sec: Optional[float] = Field(default=None, ge=0.0)
    """Throughput."""

    bytes_recv_per_sec: Optional[float] = Field(default=None, ge=0.0)
    """Throughput."""

    packets_sent_per_sec: Optional[float] = Field(default=None, ge=0.0)
    """Reliability indicator."""

    packets_recv_per_sec: Optional[float] = Field(default=None, ge=0.0)
    """Reliability indicator."""

    err_in_per_sec: Optional[float] = Field(default=None, ge=0.0)
    """Reliability indicator."""

    err_out_per_sec: Optional[float] = Field(default=None, ge=0.0)
    """Reliability indicator."""

    drop_in_per_sec: Optional[float] = Field(default=None, ge=0.0)
    """Reliability indicator."""

    drop_out_per_sec: Optional[float] = Field(default=None, ge=0.0)
    """Reliability indicator."""

class NetworkInterface(BaseModel):
    """Interface card configuration and status."""

    name: str
    """OS NIC name."""

    type: IFaceType = "unknown"
    """Ethernet/Wi-FI/etc."""

    is_up: bool
    """Link/admin up."""

    speed_mbps: Optional[float] = Field(default=None, ge=0.0)
    """Link property."""

    duplex: Optional[Literal["full", "half", "unknown"]] = "unknown"
    """Link property."""

    mtu: Optional[int] = Field(default=None, ge=0)
    """Link property."""

    addresses = AddressInfo
    """IP/MAC."""

    counters: Optional[InterfaceCounters] = None
    """Live rates."""

class ConnectionStat(BaseModel):
    """Socket table sample."""

    protocol: Protocol = "tcp"
    """Transport."""

    local_addr: Optional[Tuple[str, int]] = None
    """Endpoint. (ip, port)"""

    remote_addr: Optional[Tuple[str, int]] = None
    """Endpoint. (ip, port)"""

    status: Optional[str] = None
    """e.g. ESTABLISHED, LISTEN"""

    pid: Optional[int] = None
    """Owning process."""

class LatencyProbe(BaseModel):
    """Simple synthetic check to key hosts."""

    name: str
    """Label like: gateway, dns, internet."""

    target: str
    """Host/IP."""

    rtt_ms: Optional[float] = Field(default=None, ge=0.0)
    """MS round-trip."""

    packet_loss_pct: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    """% over the probe window."""

class NetworkModel(BaseModel):
    """Aggregate Network Model."""

    timestamp: datetime = Field(default_factory=datetime.now)
    """Collection time."""

    interfaces: List[NetworkInterface]
    """NICs."""

    connections_sample: Optional[List[ConnectionStat]] = None
    """Optional socket sample."""

    probes: Optional[List[LatencyProbe]] = None
    """Connectivity checks."""

# Hardware Health: Temps, Fans, Battery/Power, GPU

class TempSensorReading(BaseModel):
    """Sensor temperature."""

    name: str
    """Sensor name (CPU, GPU, NVME0, etc.)"""

    temperature_c: Optional[float] = None
    """Temperature reading in °C."""

class FanReading(BaseModel):
    """Fan reading."""

    name: str
    """Fan name."""

    rpm: Optional[int] = Field(default=None, ge=0)
    """Fan speed in RPM."""

class BatteryStatus(BaseModel):
    """Protable power status."""

    present: bool
    """Wheter a battery exists."""

    percent: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    """Charge %, 0-100"""

    charge_watts: Optional[float] = Field(default=None, ge=0.0)
    """Positive flow rate."""

    discharge_watts: Optional[float] = Field(default=None, ge=0.0)
    """Positive flow rate."""

    is_charging: Optional[bool] = None
    """Charging state."""

    cycles: Optional[int] = Field(default=None, ge=0.0)
    """Lifetime charge cycles."""

    health_pct: Optional[float] = Field(default=None, ge=0.0)
    """Manufacturer health estimate."""

    design_capacity_wh: Optional[float] = Field(default=None, ge=0.0)
    """Energy capacity."""

    full_charge_capacity_wh: Optional[float] = Field(default=None, ge=0.0)
    """Energy capacity."""

class GPUProcess(BaseModel):
    """Per-process GPU usage row."""
    
    pid: int
    """Process ID."""

    name: str
    """Process name."""

    gpu_util_pct: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    """Device utilization."""

    vram_bytes: Optional[int] = Field(default=None, ge=0)
    """VRAM consumed."""

class GPUModel(BaseModel):
    """GPU device panel."""

    name: str
    """Identity."""

    vendor: Optional[str] = None
    """Identity."""

    driver_version: Optional[str] = None
    """Identity."""

    usage_pct: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    """Telementry."""

    vram_total_bytes: Optional[int] = Field(default=None, ge=0)
    """Telementry."""

    vram_used_bytes: Optional[int] = Field(default=None, ge=0)
    """Telementry."""

    temperature_c: Optional[float] = None
    """Telementry."""

    power_watts: Optional[float] = Field(default=None, ge=0.0)
    """Telementry."""

    processes: Optional[List[GPUProcess]] = None
    """Top VRAM/util consumers."""

class HardwareHealthModel(BaseModel):
    """Hardware Health Model."""

    timestamp: datetime = Field(default_factory=datetime.now)
    """Collection time."""

    temperatures: Optional[List[TempSensorReading]] = None
    """Temperatures."""

    fans: Optional[List[FanReading]] = None
    """Fans."""

    battery: Optional[BatteryStatus] = None
    """Battery."""

    gpus: Optional[List[GPUModel]] = None
    """GPUs"""

# OS and Processes, Services, Uptime/boot

class TopIOProcess(BaseModel):
    """Top process."""

    pid: int
    """Process ID."""

    name: str
    """Process name."""

    read_bytes_per_sec: Optional[float] = Field(default=None, ge=0.0)
    """Process IO rate."""

    write_bytes_per_sec: Optional[float] = Field(default=None, ge=0.0)
    """Process IO rate."""

class ProcessSnapshot(BaseModel):
    """System process state aggregate."""

    total_processes: Optional[int] = Field(default=None, ge=0.0)
    """Counts by state."""

    runnning: Optional[int] = Field(default=None, ge=0)
    """Counts by state."""

    sleeping: Optional[int] = Field(default=None, ge=0)
    """Counts by state."""

    stopped: Optional[int] = Field(default=None, ge=0)
    """Counts by state."""

    zombies: Optional[int] = Field(default=None, ge=0)
    """Counts by state."""

    top_cpu: Optional[List[TopCPUProcess]] = None
    """CPU leaderboard."""

    top_mem: Optional[List[TopMemoryProcess]] = None
    """Memory leaderboard."""

    top_io: Optional[List[TopIOProcess]] = None
    """IO leaderboard"""

class ServiceStatus(BaseModel):
    """Sercice status."""

    name: str
    """Service/daemon identifier."""

    state: ServiceState
    """Running/stopped/etc."""

    uptime_s: Optional[float] = Field(default=None, ge=0.0)
    """Stability indicator."""

    restart_count: Optional[int] = Field(default=None, ge=0)
    """Stability indicator."""

class ServicesModel(BaseModel):
    """Services Model."""

    timestamp: datetime = Field(default_factory=datetime.now)
    """Collection time."""

    critical: Optional[List[ServiceStatus]] = None
    """Grouped for UI emphasis."""

    others: Optional[List[ServiceStatus]] = None
    """Grouped for UI emphasis."""

class BootInfo(BaseModel):
    """Boot information."""

    last_boot_time: Optional[datetime] = None
    """Last system boot time."""

    uptime_s: Optional[float] = Field(default=None, ge=0.0)
    """Seconds since boot."""

    previous_boot_times: Optional[List[datetime]] = None
    """History (optional)."""

# Reliability and Logs, Crashes

class LogEvent(BaseModel):
    """Normalized log/event entry."""

    time: datetime
    """Facility/channel."""

    source: str
    """Facility/channel."""

    severity: Severity
    """Severity."""

    code: Optional[str] = None
    """Optional error/event code."""

    message: str
    """Human-readable message."""

    count: Optional[int] = Field(default=None, ge=1)
    """Collapsed repetition count."""

class LogsModel(BaseModel):
    """Logs Model."""

    timestamp: datetime = Field(default_factory=datetime.now)
    """Collection time."""

    recent_critical: Optional[List[LogEvent]] = None
    """Bucket for dashboard."""

    recent_warnings: Optional[List[LogEvent]] = None
    """Bucket for dashboard."""

class CrashRecord(BaseModel):
    """Crash/BSOD/panic entry."""

    time: datetime
    """Faulting module/process time."""

    component: str
    """Faulting module/process name."""

    type: Literal["app_crash", "driver_fault", "kernal_panic", "bsod", "other"]
    """Type of fault."""

    exit_code: Optional[str] = None
    """Diagnostic reference."""

    dump_path: Optional[str] = None
    """Diagnostic reference."""

class CrashMonitorModel(BaseModel):
    """Crash Monitor Model."""

    timestamp: datetime
    """Time."""

    recent: Optional[List[CrashRecord]] = None
    """Recent crash list for triage."""

# Security Health

class SecurityFinding(BaseModel):
    """Security finding."""

    time: datetime
    """Human-reviewable time."""

    tite: str
    """Human-reviewable title."""

    severity: Severity
    """Severity."""

    details: Optional[str] = None
    """Human-reviewable details."""

class SecurityModel(BaseModel):
    """Endpoint protection posture."""
    
    timestamp: datetime = Field(default_factory=datetime.now)
    """Collection time."""

    firewall: FirewallState = "unknown"
    """On/off/unknown."""

    av: AVState = "unknown"
    """AV health."""

    av_definitions_age_days: Optional[float] = Field(default=None, ge=0.0)
    """Staleness of signature updates."""

    suspicious_processes: Optional[List[int]] = None
    """PIDs flagged by heuristics."""

    findings: Optional[list[SecurityFinding]] = None
    """Event list."""

# Virtualization / Containers

class ContainerStat(BaseModel):
    """Container statistics."""

    id: str
    """Container ID."""

    name: Optional[str] = None
    """Container name."""

    cpu_pct: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    """Resource."""

    mem_bytes: Optional[int] = Field(default=None, ge=0)
    """Resource."""

    mem_limit_bytes: Optional[int] = Field(default=None, ge=0)
    """Resource."""

    net_rx_bytes_per_sec: Optional[float] = Field(default=None, ge=0.0)
    """Network rate."""

    net_tx_bytes_per_sec: Optional[float] = Field(default=None, ge=0.0)
    """Network rate."""

    state: Optional[str] = None
    """Hypervisor-reported state (running, exited, paused)"""

class VMStat(BaseModel):
    """VM Statistics."""

    name: str
    """Allocation."""

    vcpu_count: Optional[int] = Field(default=None, ge=1)
    """Allocation."""

    cpu_pct: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    """Utilization."""

    mem_bytes: Optional[int] = Field(default=None, ge=0)
    """Utilization."""

    mem_limit_bytes: Optional[int] = Field(default=None, ge=0)
    """Utilization"""

    state: Optional[str] = None
    """Running, exited, paused"""

class VirtualizationModel(BaseModel):
    """Virtualization Model."""

    timestamp: datetime = Field(default_factory=datetime.now)
    """Time."""

    Containers: Optional[List[ContainerStat]] = None
    """Hypervisor/platform ID (Docker, KVM, Hyper-V, etc.)"""

    vms: Optional[List[VMStat]] = None
    """Hypervisor/platform ID (Docker, KVM, Hyper-V, etc.)"""

    hypervisor: Optional[str] = None
    """Hypervisor/platform ID (Docker, KVM, Hyper-V, etc.)"""

# Cloud / Remote Connectivity

class EndpointHealth(BaseModel):
    """Endpoint Health."""
    
    name: str
    """Friendly label. (Auth API, S3, etc.)"""

    url_or_host: str
    """Target."""

    status: Literal["up", "degraded", "down", "unknown"] = "unknown"
    """Probe result."""

    latency_ms: Optional[float] = Field(default=None, ge=0.0)
    """MS latency."""

    last_ok: Optional[datetime] = None
    """Diagnostic."""

    http_status: Optional[int] = None
    """Diagnostic."""

    error: Optional[str] = None
    """Diagnostic."""

class RemoteConnectivityModel(BaseModel):
    """Remote Connectivity Model."""

    timestamp: datetime = Field(default_factory=datetime.now)
    """Time."""

    endpoints: Optional[List[EndpointHealth]] = None
    """Key remote checks."""

# Alerts

class Alert(BaseModel):
    """Normalized alert across panels."""

    time: datetime = Field(default_factory=datetime.now)
    """Time."""

    scope: Literal[
        "cpu", "ram", "storage", "network", "hardware", "gpu",
        "processes", "services", "boot", "logs", "crash", 
        "security", "virtualization", "remote", "system"
    ]
    """Subsystem."""

    severity: Severity
    """Severity."""

    title: str
    """Message."""

    details: Optional[str] = None
    """Message context."""

# Top-level Snapshot

class HostInfo(BaseModel):
    """Describes the host producing telementry."""

    hostname: Optional[str] = None
    """Device name."""

    os: OSType = "unknown"
    """Platform identity."""

    os_version: Optional[str] = None
    """Platform identity."""

    kernel_version: Optional[str] = None
    """Platform identity."""

    arch: Optional[str] = None
    """Platform identity."""

    serial_or_uuid: Optional[str] = None
    """Asset identifier if available."""

    tags: Optional[Dict[str, str]] = None
    """Arbitrary metadata"""

class SystemHealthSnapShot(BaseModel):
    """A single collection cycle aggregating all panels."""

    # Metadata
    collected_at: datetime = Field(default_factory=datetime.now)
    """Snapshot time."""

    sample_interval_s: Optional[float] = Field(default=None, ge=0.0)
    """Sampling window for rate metrics."""

    host: HostInfo
    """Host identity"""

    # Major panels
    cpu: Optional[CPUModel] = None
    ram: Optional[RAMModel] = None
    storage: Optional[StorageModel] = None
    network: Optional[NetworkModel] = None
    hardware: Optional[HardwareHealthModel] = None
    processes: Optional[ProcessSnapshot] = None
    services: Optional[ServicesModel] = None
    boot: Optional[BootInfo] = None
    logs: Optional[LogsModel] = None
    crash: Optional[CrashMonitorModel] = None
    security: Optional[SecurityModel] = None
    virtualization: Optional[VirtualizationModel] = None
    remote: Optional[RemoteConnectivityModel] = None

    # Derived
    alerts: Optional[List[Alert]] = None


                                         