package IntrusionDetectionSystem;

import java.time.Instant;
import java.time.format.DateTimeFormatter;

public final class PacketMetadata {

    public enum Protocol {
        TCP,
        UDP,
        ICMP,
        OTHER
    }

    private final long timestampMillis;
    private final int packetLength;
    private final String sourceAddress;
    private final String destinationAddress;
    private final Integer sourcePort;
    private final Integer destinationPort;
    private final Protocol protocol;
    private final boolean ipPacket;
    private final boolean ipv6;
    private final boolean fragmented;
    private final boolean tcpSyn;
    private final boolean tcpAck;
    private final boolean tcpFin;
    private final boolean tcpRst;
    private final boolean tcpPsh;
    private final boolean tcpUrg;

    public PacketMetadata(
            long timestampMillis,
            int packetLength,
            String sourceAddress,
            String destinationAddress,
            Integer sourcePort,
            Integer destinationPort,
            Protocol protocol,
            boolean ipPacket,
            boolean ipv6,
            boolean fragmented,
            boolean tcpSyn,
            boolean tcpAck,
            boolean tcpFin,
            boolean tcpRst,
            boolean tcpPsh,
            boolean tcpUrg
    ) {
        if (packetLength < 0) {
            throw new IllegalArgumentException("packetLength must not be negative");
        }
        if (protocol == null) {
            throw new IllegalArgumentException("protocol must not be null");
        }
        this.timestampMillis = timestampMillis;
        this.packetLength = packetLength;
        this.sourceAddress = sourceAddress;
        this.destinationAddress = destinationAddress;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.protocol = protocol;
        this.ipPacket = ipPacket;
        this.ipv6 = ipv6;
        this.fragmented = fragmented;
        this.tcpSyn = tcpSyn;
        this.tcpAck = tcpAck;
        this.tcpFin = tcpFin;
        this.tcpRst = tcpRst;
        this.tcpPsh = tcpPsh;
        this.tcpUrg = tcpUrg;
    }

    public long getTimestampMillis() {
        return timestampMillis;
    }

    public int getPacketLength() {
        return packetLength;
    }

    public String getSourceAddress() {
        return sourceAddress;
    }

    public String getDestinationAddress() {
        return destinationAddress;
    }

    public Integer getSourcePort() {
        return sourcePort;
    }

    public Integer getDestinationPort() {
        return destinationPort;
    }

    public Protocol getProtocol() {
        return protocol;
    }

    public boolean isIpPacket() {
        return ipPacket;
    }

    public boolean isIpv6() {
        return ipv6;
    }

    public boolean isFragmented() {
        return fragmented;
    }

    public boolean isTcpSyn() {
        return tcpSyn;
    }

    public boolean isTcpAck() {
        return tcpAck;
    }

    public boolean isTcpFin() {
        return tcpFin;
    }

    public boolean isTcpRst() {
        return tcpRst;
    }

    public boolean isTcpPsh() {
        return tcpPsh;
    }

    public boolean isTcpUrg() {
        return tcpUrg;
    }

    public boolean hasAnyTcpFlag() {
        return tcpSyn || tcpAck || tcpFin || tcpRst || tcpPsh || tcpUrg;
    }

    public String getSourceEndpoint() {
        return formatEndpoint(sourceAddress, sourcePort);
    }

    public String getDestinationEndpoint() {
        return formatEndpoint(destinationAddress, destinationPort);
    }

    public String toHumanString() {
        return DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochMilli(timestampMillis))
                + " " + protocol
                + " " + getSourceEndpoint()
                + " -> " + getDestinationEndpoint()
                + " length=" + packetLength
                + (fragmented ? " fragmented" : "");
    }

    static String formatEndpoint(String address, Integer port) {
        String value = address == null || address.isEmpty() ? "-" : address;
        if (port == null) {
            return value;
        }
        if (value.indexOf(':') >= 0 && !value.startsWith("[")) {
            value = "[" + value + "]";
        }
        return value + ":" + port;
    }
}
