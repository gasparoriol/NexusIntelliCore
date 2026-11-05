import org.springframework.web.bind.annotation.*;
import java.io.*;

@RestController
public class VulnerableSpringRead {
    @GetMapping("/download")
    public String download(@RequestParam String filename) throws IOException {
        FileInputStream fis = new FileInputStream("/var/data/" + filename);
        return "done";
    }
}

