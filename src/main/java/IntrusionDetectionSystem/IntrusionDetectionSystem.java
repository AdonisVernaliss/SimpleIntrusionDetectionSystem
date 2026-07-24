package IntrusionDetectionSystem;

import org.pcap4j.core.BpfProgram;
import org.pcap4j.core.NotOpenException;
import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapHandle;
import org.pcap4j.core.PcapNativeException;
import org.pcap4j.core.PcapNetworkInterface;
import org.pcap4j.core.PcapStat;
import org.pcap4j.core.Pcaps;
import org.pcap4j.packet.Packet;

import java.io.EOFException;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.sql.Timestamp;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicBoolean;

public final class IntrusionDetectionSystem {

    private static final int READ_TIMEOUT_MILLIS = 100;

    private IntrusionDetectionSystem() {
    }

    public static void main(String[] args) {
        int exitCode = run(args, System.out, System.err);
        if (exitCode != 0) {
            System.exit(exitCode);
        }
    }

    static int run(String[] args, PrintStream output, PrintStream error) {
        CommandLineOptions options;
        try {
            options = CommandLineOptions.parse(args);
        } catch (IllegalArgumentException exception) {
            error.println("Error: " + exception.getMessage());
            error.println("Run with --help to see available options.");
            return 2;
        }

        if (options.isHelp()) {
            output.print(CommandLineOptions.helpText());
            return 0;
        }

        try {
            if (options.isListInterfaces()) {
                printInterfaces(output);
                return 0;
            }
            return capture(options, output, error);
        } catch (UnsatisfiedLinkError errorLoadingLibrary) {
            error.println("Error: libpcap or Npcap could not be loaded.");
            error.println("Install the native packet-capture library and try again.");
            return 1;
        } catch (PcapNativeException exception) {
            error.println("Packet capture error: " + cleanMessage(exception));
            if (looksLikePermissionError(exception.getMessage())) {
                error.println("The selected interface requires packet-capture privileges.");
            }
            return 1;
        } catch (IOException exception) {
            error.println("I/O error: " + cleanMessage(exception));
            return 1;
        } catch (NotOpenException exception) {
            error.println("Capture was closed unexpectedly: " + cleanMessage(exception));
            return 1;
        }
    }

    private static int capture(
            CommandLineOptions options,
            PrintStream output,
            PrintStream error
    ) throws PcapNativeException, IOException, NotOpenException {
        PrintStream status = options.isJson() ? error : output;
        boolean offline = options.getInputFile() != null;
        PcapNetworkInterface networkInterface = null;
        PcapHandle handle;

        if (offline) {
            File input = new File(options.getInputFile());
            if (!input.isFile() || !input.canRead()) {
                throw new IOException("PCAP file is not readable: " + input.getPath());
            }
            handle = Pcaps.openOffline(input.getAbsolutePath());
            status.println("Analyzing PCAP: " + input.getAbsolutePath());
        } else {
            networkInterface = selectInterface(options.getInterfaceName());
            PcapNetworkInterface.PromiscuousMode mode = options.isPromiscuous()
                    ? PcapNetworkInterface.PromiscuousMode.PROMISCUOUS
                    : PcapNetworkInterface.PromiscuousMode.NONPROMISCUOUS;
            handle = networkInterface.openLive(
                    options.getSnapshotLength(),
                    mode,
                    READ_TIMEOUT_MILLIS
            );
            status.println("Monitoring interface: " + interfaceLabel(networkInterface));
            status.println("Press Ctrl+C to stop.");
        }

        AtomicBoolean stopRequested = new AtomicBoolean(false);
        Thread shutdownHook = new Thread(
                new Runnable() {
                    @Override
                    public void run() {
                        stopRequested.set(true);
                    }
                },
                "ids-shutdown"
        );
        Runtime.getRuntime().addShutdownHook(shutdownHook);

        long startedAt = System.nanoTime();
        PacketStatistics statistics = new PacketStatistics();
        PacketAnalyzer analyzer = new SimplePacketAnalyzer();
        IntrusionDetectionEngine engine = new SimpleIntrusionDetectionEngine(
                options.detectorConfig()
        );

        try (PcapHandle captureHandle = handle;
             AlertWriter alertWriter = new AlertWriter(
                     output,
                     options.isJson(),
                     options.getLogFile()
             )) {
            String filter = options.getFilter();
            if (filter != null && !filter.trim().isEmpty()) {
                captureHandle.setFilter(
                        filter,
                        BpfProgram.BpfCompileMode.OPTIMIZE
                );
                status.println("BPF filter: " + filter);
            }

            while (!stopRequested.get()
                    && !limitReached(options, statistics, startedAt)) {
                Packet packet;
                try {
                    packet = captureHandle.getNextPacketEx();
                } catch (TimeoutException exception) {
                    continue;
                } catch (EOFException exception) {
                    break;
                }

                Timestamp timestamp = captureHandle.getTimestamp();
                long timestampMillis = timestamp == null
                        ? System.currentTimeMillis()
                        : timestamp.getTime();
                PacketMetadata metadata;
                List<SecurityAlert> alerts;
                try {
                    metadata = analyzer.analyze(packet, timestampMillis);
                    statistics.record(metadata);
                    alerts = engine.detect(metadata);
                } catch (RuntimeException exception) {
                    statistics.recordAnalysisError();
                    if (options.isVerbose()) {
                        status.println("Skipped packet that could not be analyzed: "
                                + cleanMessage(exception));
                    }
                    continue;
                }

                if (options.isVerbose()) {
                    status.println("Packet: " + metadata.toHumanString());
                }

                for (SecurityAlert alert : alerts) {
                    alertWriter.write(alert);
                }
                statistics.recordAlerts(alerts.size());
            }

            if (!offline) {
                readKernelStatistics(captureHandle, statistics);
            }
        } finally {
            removeShutdownHook(shutdownHook);
        }

        status.println(statistics.toHumanString(System.nanoTime() - startedAt));
        return 0;
    }

    private static boolean limitReached(
            CommandLineOptions options,
            PacketStatistics statistics,
            long startedAt
    ) {
        if (options.getPacketLimit() > 0
                && statistics.getPackets() >= options.getPacketLimit()) {
            return true;
        }
        return options.getDurationSeconds() > 0
                && System.nanoTime() - startedAt
                >= options.getDurationSeconds() * 1_000_000_000L;
    }

    private static PcapNetworkInterface selectInterface(String requestedName)
            throws PcapNativeException {
        if (requestedName != null) {
            PcapNetworkInterface requested = Pcaps.getDevByName(requestedName);
            if (requested == null) {
                throw new PcapNativeException(
                        "network interface not found: " + requestedName
                                + ". Run with --list-interfaces."
                );
            }
            return requested;
        }

        List<PcapNetworkInterface> interfaces = safeInterfaces();
        PcapNetworkInterface bestInterface = null;
        int bestScore = Integer.MIN_VALUE;
        for (PcapNetworkInterface networkInterface : interfaces) {
            int score = interfaceScore(networkInterface);
            if (score > bestScore) {
                bestScore = score;
                bestInterface = networkInterface;
            }
        }
        if (bestInterface != null) {
            return bestInterface;
        }
        throw new PcapNativeException("no packet-capture interfaces are available");
    }

    private static int interfaceScore(PcapNetworkInterface networkInterface) {
        if (networkInterface.isLoopBack()) {
            return -1_000;
        }
        int score = 0;
        if (networkInterface.isUp()) {
            score += 40;
        }
        if (networkInterface.isRunning()) {
            score += 40;
        }
        if (networkInterface.isLocal()) {
            score += 10;
        }

        for (PcapAddress address : networkInterface.getAddresses()) {
            InetAddress inetAddress = address.getAddress();
            if (inetAddress == null || inetAddress.isLoopbackAddress()
                    || inetAddress.isMulticastAddress()) {
                continue;
            }
            score += 10;
            if (!inetAddress.isLinkLocalAddress()) {
                score += 100;
            }
            if (inetAddress instanceof Inet4Address) {
                score += 30;
            }
        }

        String name = networkInterface.getName().toLowerCase(Locale.ROOT);
        if (name.matches("^(en|eth|wlan|wl|wlp)[0-9a-z._-]*$")) {
            score += 30;
        }
        if (name.startsWith("utun")
                || name.startsWith("tun")
                || name.startsWith("tap")
                || name.startsWith("awdl")
                || name.startsWith("llw")
                || name.startsWith("bridge")
                || name.startsWith("docker")
                || name.startsWith("veth")) {
            score -= 50;
        }
        return score;
    }

    private static void printInterfaces(PrintStream output) throws PcapNativeException {
        List<PcapNetworkInterface> interfaces = safeInterfaces();
        if (interfaces.isEmpty()) {
            output.println("No packet-capture interfaces found.");
            return;
        }
        output.println("Available packet-capture interfaces:");
        for (PcapNetworkInterface networkInterface : interfaces) {
            StringBuilder addresses = new StringBuilder();
            for (PcapAddress address : networkInterface.getAddresses()) {
                if (address.getAddress() != null) {
                    if (addresses.length() > 0) {
                        addresses.append(", ");
                    }
                    addresses.append(address.getAddress().getHostAddress());
                }
            }
            output.println("  " + interfaceLabel(networkInterface)
                    + " [up=" + networkInterface.isUp()
                    + ", running=" + networkInterface.isRunning()
                    + ", loopback=" + networkInterface.isLoopBack() + "]"
                    + (addresses.length() == 0 ? "" : " addresses=" + addresses));
        }
    }

    private static List<PcapNetworkInterface> safeInterfaces() throws PcapNativeException {
        List<PcapNetworkInterface> interfaces = Pcaps.findAllDevs();
        return interfaces == null ? Collections.<PcapNetworkInterface>emptyList() : interfaces;
    }

    private static String interfaceLabel(PcapNetworkInterface networkInterface) {
        String description = networkInterface.getDescription();
        if (description == null || description.trim().isEmpty()
                || description.equals(networkInterface.getName())) {
            return networkInterface.getName();
        }
        return networkInterface.getName() + " (" + description + ")";
    }

    private static void readKernelStatistics(
            PcapHandle handle,
            PacketStatistics statistics
    ) {
        try {
            PcapStat stat = handle.getStats();
            statistics.setKernelStatistics(
                    stat.getNumPacketsReceived(),
                    stat.getNumPacketsDropped()
            );
        } catch (PcapNativeException ignored) {
            // Some capture backends do not expose statistics.
        } catch (NotOpenException ignored) {
            // The summary remains useful without kernel statistics.
        }
    }

    private static void removeShutdownHook(Thread hook) {
        try {
            Runtime.getRuntime().removeShutdownHook(hook);
        } catch (IllegalStateException ignored) {
            // The JVM is already shutting down.
        }
    }

    private static boolean looksLikePermissionError(String message) {
        if (message == null) {
            return false;
        }
        String normalized = message.toLowerCase(Locale.ROOT);
        return normalized.contains("permission")
                || normalized.contains("not permitted")
                || normalized.contains("access is denied");
    }

    private static String cleanMessage(Throwable throwable) {
        String message = throwable.getMessage();
        return message == null || message.trim().isEmpty()
                ? throwable.getClass().getSimpleName()
                : message;
    }
}
