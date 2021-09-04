package nl.dannyjelsma.cloudencrypt.upload;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class LocalTestUploader implements Uploader {
    @Override
    public String getName() {
        return "local test (development)";
    }

    @Override
    public void uploadFile(byte[] fileBytes, String fileName) {
        String location = "C:\\Users\\Danny\\Desktop\\backup-loc";
        File file = new File(location, fileName);

        try {
            if (!file.getParentFile().exists()) {
                file.getParentFile().mkdirs();
            }

            Files.write(file.toPath(), fileBytes);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
