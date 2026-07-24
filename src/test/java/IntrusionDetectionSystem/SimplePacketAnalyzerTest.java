package IntrusionDetectionSystem;

import org.junit.jupiter.api.Test;
import org.pcap4j.packet.IllegalRawDataException;
import org.pcap4j.packet.IpV4Packet;
import org.pcap4j.packet.Packet;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SimplePacketAnalyzerTest {

    @Test
    void extractsIpv4TcpMetadata() throws IllegalRawDataException {
        byte[] rawPacket = new byte[]{
                0x45, 0x00, 0x00, 0x28,
                0x00, 0x01, 0x00, 0x00,
                0x40, 0x06, 0x00, 0x00,
                (byte) 0xc0, 0x00, 0x02, 0x01,
                (byte) 0xc6, 0x33, 0x64, 0x02,
                0x30, 0x39, 0x01, (byte) 0xbb,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
                0x50, 0x02, 0x40, 0x00,
                0x00, 0x00, 0x00, 0x00
        };
        Packet packet = IpV4Packet.newPacket(rawPacket, 0, rawPacket.length);

        PacketMetadata metadata = new SimplePacketAnalyzer().analyze(packet, 1_000L);

        assertEquals(PacketMetadata.Protocol.TCP, metadata.getProtocol());
        assertEquals("192.0.2.1", metadata.getSourceAddress());
        assertEquals("198.51.100.2", metadata.getDestinationAddress());
        assertEquals(Integer.valueOf(12345), metadata.getSourcePort());
        assertEquals(Integer.valueOf(443), metadata.getDestinationPort());
        assertTrue(metadata.isTcpSyn());
        assertFalse(metadata.isTcpAck());
        assertEquals(40, metadata.getPacketLength());
    }
}
