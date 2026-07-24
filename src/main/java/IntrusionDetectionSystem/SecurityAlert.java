package IntrusionDetectionSystem;

import java.time.Instant;
import java.time.format.DateTimeFormatter;

public final class SecurityAlert {

    public enum Severity {
        LOW,
        MEDIUM,
        HIGH,
        CRITICAL
    }

    public enum Type {
        OVERSIZED_PACKET,
        WATCHED_PORT,
        TCP_NULL_SCAN,
        TCP_XMAS_SCAN,
        TCP_SYN_FIN,
        PORT_SCAN,
        HOST_SCAN,
        SYN_FLOOD,
        UDP_FLOOD,
        ICMP_FLOOD
    }

    private final long timestampMillis;
    private final Severity severity;
    private final Type type;
    private final String sourceAddress;
    private final String destinationAddress;
    private final Integer sourcePort;
    private final Integer destinationPort;
    private final String message;

    public SecurityAlert(
            long timestampMillis,
            Severity severity,
            Type type,
            String sourceAddress,
            String destinationAddress,
            Integer sourcePort,
            Integer destinationPort,
            String message
    ) {
        if (severity == null || type == null || message == null) {
            throw new IllegalArgumentException("severity, type, and message are required");
        }
        this.timestampMillis = timestampMillis;
        this.severity = severity;
        this.type = type;
        this.sourceAddress = sourceAddress;
        this.destinationAddress = destinationAddress;
        this.sourcePort = sourcePort;
        this.destinationPort = destinationPort;
        this.message = message;
    }

    public long getTimestampMillis() {
        return timestampMillis;
    }

    public Severity getSeverity() {
        return severity;
    }

    public Type getType() {
        return type;
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

    public String getMessage() {
        return message;
    }

    public String toHumanString() {
        String timestamp = DateTimeFormatter.ISO_INSTANT.format(Instant.ofEpochMilli(timestampMillis));
        return "[" + timestamp + "] "
                + severity + " " + type + " "
                + PacketMetadata.formatEndpoint(sourceAddress, sourcePort)
                + " -> "
                + PacketMetadata.formatEndpoint(destinationAddress, destinationPort)
                + " - " + message;
    }

    public String toJson() {
        return "{"
                + "\"timestamp\":" + quote(DateTimeFormatter.ISO_INSTANT.format(
                Instant.ofEpochMilli(timestampMillis))) + ","
                + "\"severity\":" + quote(severity.name()) + ","
                + "\"type\":" + quote(type.name()) + ","
                + "\"source\":" + nullableQuote(sourceAddress) + ","
                + "\"sourcePort\":" + nullableNumber(sourcePort) + ","
                + "\"destination\":" + nullableQuote(destinationAddress) + ","
                + "\"destinationPort\":" + nullableNumber(destinationPort) + ","
                + "\"message\":" + quote(message)
                + "}";
    }

    private static String nullableQuote(String value) {
        return value == null ? "null" : quote(value);
    }

    private static String nullableNumber(Integer value) {
        return value == null ? "null" : Integer.toString(value);
    }

    private static String quote(String value) {
        StringBuilder escaped = new StringBuilder(value.length() + 2);
        escaped.append('"');
        for (int i = 0; i < value.length(); i++) {
            char character = value.charAt(i);
            switch (character) {
                case '"':
                    escaped.append("\\\"");
                    break;
                case '\\':
                    escaped.append("\\\\");
                    break;
                case '\b':
                    escaped.append("\\b");
                    break;
                case '\f':
                    escaped.append("\\f");
                    break;
                case '\n':
                    escaped.append("\\n");
                    break;
                case '\r':
                    escaped.append("\\r");
                    break;
                case '\t':
                    escaped.append("\\t");
                    break;
                default:
                    if (character < 0x20) {
                        escaped.append(String.format("\\u%04x", (int) character));
                    } else {
                        escaped.append(character);
                    }
            }
        }
        return escaped.append('"').toString();
    }
}
