package IntrusionDetectionSystem;

import java.io.BufferedWriter;
import java.io.Closeable;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;

final class AlertWriter implements Closeable {

    private final PrintStream output;
    private final boolean jsonOutput;
    private final BufferedWriter logWriter;

    AlertWriter(PrintStream output, boolean jsonOutput, String logFile) throws IOException {
        this.output = output;
        this.jsonOutput = jsonOutput;
        if (logFile == null) {
            this.logWriter = null;
        } else {
            Path path = Paths.get(logFile).toAbsolutePath().normalize();
            Path parent = path.getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            this.logWriter = Files.newBufferedWriter(
                    path,
                    StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.APPEND
            );
        }
    }

    void write(SecurityAlert alert) throws IOException {
        output.println(jsonOutput ? alert.toJson() : alert.toHumanString());
        if (logWriter != null) {
            logWriter.write(alert.toJson());
            logWriter.newLine();
            logWriter.flush();
        }
    }

    @Override
    public void close() throws IOException {
        if (logWriter != null) {
            logWriter.close();
        }
    }
}
