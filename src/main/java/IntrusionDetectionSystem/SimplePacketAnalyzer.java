package IntrusionDetectionSystem;

import org.pcap4j.packet.IcmpV4CommonPacket;
import org.pcap4j.packet.IcmpV6CommonPacket;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.IpV6Packet;
import org.pcap4j.packet.Packet;
import org.pcap4j.packet.TcpPacket;
import org.pcap4j.packet.UdpPacket;

public final class SimplePacketAnalyzer implements PacketAnalyzer {

    @Override
    public PacketMetadata analyze(Packet packet, long timestampMillis) {
        if (packet == null) {
            throw new IllegalArgumentException("packet must not be null");
        }

        String sourceAddress = null;
        String destinationAddress = null;
        boolean ipPacket = false;
        boolean ipv6 = false;
        boolean fragmented = false;

        IpV4Packet ipV4Packet = packet.get(IpV4Packet.class);
        if (ipV4Packet != null) {
            IpV4Packet.IpV4Header header = ipV4Packet.getHeader();
            sourceAddress = header.getSrcAddr().getHostAddress();
            destinationAddress = header.getDstAddr().getHostAddress();
            ipPacket = true;
            fragmented = header.getMoreFragmentFlag() || header.getFragmentOffset() != 0;
        } else {
            IpV6Packet ipV6Packet = packet.get(IpV6Packet.class);
            if (ipV6Packet != null) {
                sourceAddress = ipV6Packet.getHeader().getSrcAddr().getHostAddress();
                destinationAddress = ipV6Packet.getHeader().getDstAddr().getHostAddress();
                ipPacket = true;
                ipv6 = true;
            }
        }

        PacketMetadata.Protocol protocol = PacketMetadata.Protocol.OTHER;
        Integer sourcePort = null;
        Integer destinationPort = null;
        boolean syn = false;
        boolean ack = false;
        boolean fin = false;
        boolean rst = false;
        boolean psh = false;
        boolean urg = false;

        TcpPacket tcpPacket = packet.get(TcpPacket.class);
        if (tcpPacket != null) {
            TcpPacket.TcpHeader header = tcpPacket.getHeader();
            protocol = PacketMetadata.Protocol.TCP;
            sourcePort = header.getSrcPort().valueAsInt();
            destinationPort = header.getDstPort().valueAsInt();
            syn = header.getSyn();
            ack = header.getAck();
            fin = header.getFin();
            rst = header.getRst();
            psh = header.getPsh();
            urg = header.getUrg();
        } else {
            UdpPacket udpPacket = packet.get(UdpPacket.class);
            if (udpPacket != null) {
                protocol = PacketMetadata.Protocol.UDP;
                sourcePort = udpPacket.getHeader().getSrcPort().valueAsInt();
                destinationPort = udpPacket.getHeader().getDstPort().valueAsInt();
            } else if (packet.contains(IcmpV4CommonPacket.class)
                    || packet.contains(IcmpV6CommonPacket.class)) {
                protocol = PacketMetadata.Protocol.ICMP;
            }
        }

        return new PacketMetadata(
                timestampMillis,
                packet.length(),
                sourceAddress,
                destinationAddress,
                sourcePort,
                destinationPort,
                protocol,
                ipPacket,
                ipv6,
                fragmented,
                syn,
                ack,
                fin,
                rst,
                psh,
                urg
        );
    }
}
