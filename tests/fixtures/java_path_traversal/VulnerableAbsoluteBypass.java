import org.springframework.web.bind.annotation.*;
import java.io.*;

@RestController
public class VulnerableAbsoluteBypass {
    @GetMapping("/file")
    public String read(@RequestParam String path) throws IOException {
        if (!path.contains("..")) {   // FALSE GUARD — allows /etc/passwd
            FileInputStream fis = new FileInputStream(path);
            return "ok";
        }
        return "rejected";
    }
}

