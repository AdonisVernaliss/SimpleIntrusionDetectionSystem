package IntrusionDetectionSystem;

import java.util.Locale;

final class PacketStatistics {

    private long packets;
    private long bytes;
    private long tcpPackets;
    private long udpPackets;
    private long icmpPackets;
    private long otherPackets;
    private long ipv4Packets;
    private long ipv6Packets;
    private long fragmentedPackets;
    private long analysisErrors;
    private long alerts;
    private long capturedByKernel = -1;
    private long droppedByKernel = -1;

    void record(PacketMetadata packet) {
        packets++;
        bytes += packet.getPacketLength();
        if (packet.isIpPacket()) {
            if (packet.isIpv6()) {
                ipv6Packets++;
            } else {
                ipv4Packets++;
            }
        }
        if (packet.isFragmented()) {
            fragmentedPackets++;
        }
        switch (packet.getProtocol()) {
            case TCP:
                tcpPackets++;
                break;
            case UDP:
                udpPackets++;
                break;
            case ICMP:
                icmpPackets++;
                break;
            default:
                otherPackets++;
        }
    }

    void recordAlerts(int count) {
        alerts += count;
    }

    void recordAnalysisError() {
        analysisErrors++;
    }

    void setKernelStatistics(long captured, long dropped) {
        capturedByKernel = captured;
        droppedByKernel = dropped;
    }

    long getPackets() {
        return packets;
    }

    long getAlerts() {
        return alerts;
    }

    String toHumanString(long elapsedNanos) {
        double seconds = Math.max(elapsedNanos / 1_000_000_000.0, 0.001);
        StringBuilder summary = new StringBuilder();
        summary.append("Summary: packets=").append(packets)
                .append(", bytes=").append(bytes)
                .append(", TCP=").append(tcpPackets)
                .append(", UDP=").append(udpPackets)
                .append(", ICMP=").append(icmpPackets)
                .append(", other=").append(otherPackets)
                .append(", IPv4=").append(ipv4Packets)
                .append(", IPv6=").append(ipv6Packets)
                .append(", fragments=").append(fragmentedPackets)
                .append(", analysisErrors=").append(analysisErrors)
                .append(", alerts=").append(alerts)
                .append(", rate=")
                .append(String.format(Locale.ROOT, "%.1f", packets / seconds))
                .append(" packets/s");
        if (capturedByKernel >= 0) {
            summary.append(", kernelReceived=").append(capturedByKernel);
        }
        if (droppedByKernel >= 0) {
            summary.append(", kernelDropped=").append(droppedByKernel);
        }
        return summary.toString();
    }
}
