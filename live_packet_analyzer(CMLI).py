import threading
import psutil
import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel

console = Console()
packet_list = []
MAX_DISPLAY = 15


def get_interface():
    """Uses psutil for more accurate interface detection."""
    addrs = psutil.net_if_addrs()
    for interface, snics in addrs.items():
        for snic in snics:
            if snic.family == 2 and not snic.address.startswith("127."):
                return interface
    return None


def process_packet(packet):
    if IP in packet:
        proto = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "IP"
        if DNS in packet: proto = "DNS"

        info = {
            "time": datetime.datetime.now().strftime("%H:%M:%S"),
            "src": packet[IP].src,
            "dst": packet[IP].dst,
            "proto": proto,
            "len": len(packet),
            "info": f"Port: {packet.sport} -> {packet.dport}" if hasattr(packet, 'sport') else ""
        }
        packet_list.append(info)
        if len(packet_list) > MAX_DISPLAY:
            packet_list.pop(0)


def generate_table():
    table = Table(title="📡 Live Network Traffic", show_header=True, header_style="bold magenta")
    table.add_column("Time", style="dim")
    table.add_column("Source", style="cyan")
    table.add_column("Destination", style="green")
    table.add_column("Protocol", style="yellow")
    table.add_column("Length", justify="right")
    table.add_column("Extra Info")

    for p in reversed(packet_list):
        table.add_row(p['time'], p['src'], p['dst'], p['proto'], str(p['len']), p['info'])
    return table


if __name__ == "__main__":
    iface = get_interface()
    console.print(Panel(f"[bold green]Starting Sniffer on {iface}...[/bold green]\nPress Ctrl+C to stop."))

    sniffer = threading.Thread(target=lambda: sniff(iface=iface, prn=process_packet, store=0), daemon=True)
    sniffer.start()

    try:
        with Live(generate_table(), refresh_per_second=2) as live:
            while True:
                live.update(generate_table())
    except KeyboardInterrupt:
        console.print("\n[bold red]Stopping...[/bold red]")
