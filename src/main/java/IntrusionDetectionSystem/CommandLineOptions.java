package IntrusionDetectionSystem;

import java.util.LinkedHashSet;
import java.util.Set;

final class CommandLineOptions {

    private boolean help;
    private boolean listInterfaces;
    private String interfaceName;
    private String inputFile;
    private String filter = "ip or ip6";
    private long packetLimit;
    private long durationSeconds;
    private int snapshotLength = 65_536;
    private boolean promiscuous = true;
    private boolean verbose;
    private boolean json;
    private String logFile;

    private long windowSeconds = 10L;
    private int portScanThreshold = 15;
    private int hostScanThreshold = 20;
    private int synThreshold = 100;
    private int udpThreshold = 250;
    private int icmpThreshold = 100;
    private int maximumPacketSize = 2_000;
    private long cooldownSeconds = 30L;
    private Set<Integer> watchedPorts = new LinkedHashSet<Integer>(
            DetectorConfig.defaults().getWatchedPorts()
    );

    static CommandLineOptions parse(String[] args) {
        if (args == null) {
            throw new IllegalArgumentException("arguments must not be null");
        }
        CommandLineOptions options = new CommandLineOptions();
        for (int index = 0; index < args.length; index++) {
            String argument = args[index];
            switch (argument) {
                case "-h":
                case "--help":
                    options.help = true;
                    break;
                case "--list-interfaces":
                    options.listInterfaces = true;
                    break;
                case "-i":
                case "--interface":
                    options.interfaceName = value(args, ++index, argument);
                    break;
                case "-r":
                case "--read":
                    options.inputFile = value(args, ++index, argument);
                    break;
                case "-f":
                case "--filter":
                    String filter = value(args, ++index, argument);
                    options.filter = "none".equalsIgnoreCase(filter) ? null : filter;
                    break;
                case "-c":
                case "--count":
                    options.packetLimit = positiveLong(value(args, ++index, argument), argument);
                    break;
                case "-d":
                case "--duration":
                    options.durationSeconds = positiveLong(value(args, ++index, argument), argument);
                    break;
                case "--snaplen":
                    options.snapshotLength = positiveInt(value(args, ++index, argument), argument);
                    if (options.snapshotLength > 1_048_576) {
                        throw new IllegalArgumentException("--snaplen must not exceed 1048576");
                    }
                    break;
                case "--no-promiscuous":
                    options.promiscuous = false;
                    break;
                case "--verbose":
                    options.verbose = true;
                    break;
                case "--json":
                    options.json = true;
                    break;
                case "--log":
                    options.logFile = value(args, ++index, argument);
                    break;
                case "--window-seconds":
                    options.windowSeconds = positiveLong(value(args, ++index, argument), argument);
                    break;
                case "--port-scan-threshold":
                    options.portScanThreshold = positiveInt(value(args, ++index, argument), argument);
                    break;
                case "--host-scan-threshold":
                    options.hostScanThreshold = positiveInt(value(args, ++index, argument), argument);
                    break;
                case "--syn-threshold":
                    options.synThreshold = positiveInt(value(args, ++index, argument), argument);
                    break;
                case "--udp-threshold":
                    options.udpThreshold = positiveInt(value(args, ++index, argument), argument);
                    break;
                case "--icmp-threshold":
                    options.icmpThreshold = positiveInt(value(args, ++index, argument), argument);
                    break;
                case "--max-packet-size":
                    options.maximumPacketSize = positiveInt(value(args, ++index, argument), argument);
                    break;
                case "--cooldown-seconds":
                    options.cooldownSeconds = nonNegativeLong(
                            value(args, ++index, argument),
                            argument
                    );
                    break;
                case "--watch-ports":
                    options.watchedPorts = parsePorts(value(args, ++index, argument));
                    break;
                default:
                    throw new IllegalArgumentException("unknown option: " + argument);
            }
        }

        if (options.interfaceName != null && options.inputFile != null) {
            throw new IllegalArgumentException("--interface and --read cannot be used together");
        }
        if (options.windowSeconds > Long.MAX_VALUE / 1_000L
                || options.cooldownSeconds > Long.MAX_VALUE / 1_000L
                || options.durationSeconds > Long.MAX_VALUE / 1_000_000_000L) {
            throw new IllegalArgumentException("time option is too large");
        }
        return options;
    }

    DetectorConfig detectorConfig() {
        return new DetectorConfig(
                windowSeconds * 1_000L,
                portScanThreshold,
                hostScanThreshold,
                synThreshold,
                udpThreshold,
                icmpThreshold,
                maximumPacketSize,
                cooldownSeconds * 1_000L,
                watchedPorts
        );
    }

    static String helpText() {
        return "Simple Intrusion Detection System\n"
                + "\n"
                + "Usage: java -jar intrusion-detection-system-1.0.0.jar [options]\n"
                + "\n"
                + "Capture source:\n"
                + "  -h, --help                  Show this help\n"
                + "      --list-interfaces       List available capture interfaces\n"
                + "  -i, --interface NAME        Capture from the named interface\n"
                + "  -r, --read FILE             Analyze an offline PCAP file\n"
                + "  -f, --filter EXPRESSION     BPF filter or \"none\" (default: ip or ip6)\n"
                + "  -c, --count NUMBER          Stop after NUMBER packets\n"
                + "  -d, --duration SECONDS      Stop after SECONDS\n"
                + "      --no-promiscuous        Disable promiscuous mode\n"
                + "      --snaplen BYTES         Snapshot length (default: 65536)\n"
                + "\n"
                + "Output:\n"
                + "      --verbose               Print metadata for every packet\n"
                + "      --json                  Print alerts as JSON Lines\n"
                + "      --log FILE              Append JSON Lines alerts to FILE\n"
                + "\n"
                + "Detection:\n"
                + "      --window-seconds N      Detection window (default: 10)\n"
                + "      --port-scan-threshold N Unique ports (default: 15)\n"
                + "      --host-scan-threshold N Unique hosts (default: 20)\n"
                + "      --syn-threshold N       SYN packets (default: 100)\n"
                + "      --udp-threshold N       UDP packets (default: 250)\n"
                + "      --icmp-threshold N      ICMP packets (default: 100)\n"
                + "      --max-packet-size N     Packet-size limit (default: 2000)\n"
                + "      --cooldown-seconds N    Repeat cooldown (default: 30)\n"
                + "      --watch-ports LIST      Comma-separated ports or \"none\"\n";
    }

    boolean isHelp() {
        return help;
    }

    boolean isListInterfaces() {
        return listInterfaces;
    }

    String getInterfaceName() {
        return interfaceName;
    }

    String getInputFile() {
        return inputFile;
    }

    String getFilter() {
        return filter;
    }

    long getPacketLimit() {
        return packetLimit;
    }

    long getDurationSeconds() {
        return durationSeconds;
    }

    int getSnapshotLength() {
        return snapshotLength;
    }

    boolean isPromiscuous() {
        return promiscuous;
    }

    boolean isVerbose() {
        return verbose;
    }

    boolean isJson() {
        return json;
    }

    String getLogFile() {
        return logFile;
    }

    private static String value(String[] args, int index, String option) {
        if (index >= args.length || args[index].isEmpty()) {
            throw new IllegalArgumentException("missing value for " + option);
        }
        return args[index];
    }

    private static int positiveInt(String raw, String option) {
        long value = positiveLong(raw, option);
        if (value > Integer.MAX_VALUE) {
            throw new IllegalArgumentException("value for " + option + " is too large");
        }
        return (int) value;
    }

    private static long positiveLong(String raw, String option) {
        long value = parseLong(raw, option);
        if (value <= 0) {
            throw new IllegalArgumentException(option + " must be positive");
        }
        return value;
    }

    private static long nonNegativeLong(String raw, String option) {
        long value = parseLong(raw, option);
        if (value < 0) {
            throw new IllegalArgumentException(option + " must not be negative");
        }
        return value;
    }

    private static long parseLong(String raw, String option) {
        try {
            return Long.parseLong(raw);
        } catch (NumberFormatException exception) {
            throw new IllegalArgumentException("invalid number for " + option + ": " + raw);
        }
    }

    private static Set<Integer> parsePorts(String raw) {
        Set<Integer> ports = new LinkedHashSet<Integer>();
        if ("none".equalsIgnoreCase(raw)) {
            return ports;
        }
        String[] values = raw.split(",");
        for (String value : values) {
            String trimmed = value.trim();
            int port = positiveInt(trimmed, "--watch-ports");
            if (port > 65_535) {
                throw new IllegalArgumentException("watched ports must be between 1 and 65535");
            }
            ports.add(port);
        }
        if (ports.isEmpty()) {
            throw new IllegalArgumentException("--watch-ports must contain a port or \"none\"");
        }
        return ports;
    }
}
