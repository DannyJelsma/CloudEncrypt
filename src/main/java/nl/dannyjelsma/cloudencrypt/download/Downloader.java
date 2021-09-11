package nl.dannyjelsma.cloudencrypt.download;

import nl.dannyjelsma.cloudencrypt.backup.BackupFolder;

import java.io.File;
import java.util.List;

public interface Downloader {

    String getName();

    List<File> downloadFiles(BackupFolder folder, long backupTime);

}
