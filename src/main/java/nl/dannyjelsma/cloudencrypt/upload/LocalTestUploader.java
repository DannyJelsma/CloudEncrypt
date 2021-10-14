package nl.dannyjelsma.cloudencrypt.upload;

import nl.dannyjelsma.cloudencrypt.backup.BackupFolder;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

public class LocalTestUploader implements Uploader {
    @Override
    public String getName() {
        return "local test (development)";
    }

    @Override
    public void uploadFile(BackupFolder folder, File originalFile, File encryptedFile, String fileName) {
        String location = "C:\\Users\\Danny\\Desktop\\test-bak";
        File file = new File(location, fileName);

        try {
            if (!file.getParentFile().exists()) {
                file.getParentFile().mkdirs();
            }

            Files.move(encryptedFile.toPath(), file.toPath());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
