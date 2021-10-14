package nl.dannyjelsma.cloudencrypt.download;

import nl.dannyjelsma.cloudencrypt.backup.BackupFolder;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class LocalTestDownloader implements Downloader {

    @Override
    public String getName() {
        return "local test (development)";
    }

    @Override
    public List<File> downloadFiles(BackupFolder folder, long backupTime) {
        File encryptedDir = new File("C:\\Users\\Danny\\Desktop\\test-bak");
        Collection<File> files = FileUtils.listFiles(encryptedDir, null, true);
        List<File> downloadedFiles = new ArrayList<>();

        for (File file : files) {
            String fileName = file.getAbsolutePath()
                    .replace(file.getName(), "")
                    .replace(encryptedDir.getAbsolutePath(), "") + file.getName();
            File destFile = new File(folder.getFolder(), fileName);

            if (!destFile.getParentFile().exists()) {
                destFile.getParentFile().mkdirs();
            }

            try {
                if (!destFile.exists()) {
                    Files.copy(file.toPath(), destFile.toPath());
                }

                downloadedFiles.add(destFile);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        return downloadedFiles;
    }
}
