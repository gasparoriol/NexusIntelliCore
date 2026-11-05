import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;

@RestController
public class SafeConfinement {
    private static final Path BASE = Paths.get("/var/data/");
    @GetMapping("/safe")
    public String read(@RequestParam String filename) throws IOException {
        Path resolved = BASE.resolve(filename).normalize();
        if (!resolved.startsWith(BASE + File.separator)) {
            throw new SecurityException("Traversal attempt");
        }
        return Files.readString(resolved);
    }
}

