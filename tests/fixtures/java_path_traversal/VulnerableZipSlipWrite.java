import java.util.zip.*;
import java.io.*;

public class VulnerableZipSlipWrite {
    void extract(ZipInputStream zis, String destDir) throws IOException {
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            File dest = new File(destDir, entry.getName());
            FileOutputStream fos = new FileOutputStream(dest);
        }
    }
}

