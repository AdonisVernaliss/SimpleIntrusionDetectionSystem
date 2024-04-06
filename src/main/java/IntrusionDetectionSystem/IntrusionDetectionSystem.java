package IntrusionDetectionSystem;

import org.pcap4j.core.*;
import org.pcap4j.packet.Packet;

import java.io.EOFException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeoutException;

public class IntrusionDetectionSystem {

    public static void main(String[] args) {
        try {
            PcapNetworkInterface networkInterface = Pcaps.getDevByName("en0");

            PcapHandle handle = networkInterface.openLive(65536, PcapNetworkInterface.PromiscuousMode.PROMISCUOUS, 10);

            PacketAnalyzer analyzer = new SimplePacketAnalyzer();
            IntrusionDetectionEngine engine = new SimpleIntrusionDetectionEngine();

            ExecutorService executorService = Executors.newFixedThreadPool(10);

            executorService.execute(() -> {
                try {
                    while (true) {
                        Packet packet = handle.getNextPacketEx();
                        analyzer.analyze(packet);
                        engine.detect(packet);
                    }
                } catch (PcapNativeException | NotOpenException | EOFException | TimeoutException e) {
                    e.printStackTrace();
                }
            });


            System.out.println("Intrusion Detection System started...");
            System.out.println("Press Enter to stop.");
            System.in.read();

            executorService.shutdown();
            handle.close();
            System.out.println("Intrusion Detection System stopped.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

