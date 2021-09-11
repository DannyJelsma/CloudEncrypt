package nl.dannyjelsma.cloudencrypt.upload;

import nl.dannyjelsma.cloudencrypt.backup.BackupFolder;

import java.io.File;

public interface Uploader {

    String getName();

    void uploadFile(BackupFolder folder, File originalFile, File encryptedFile, String fileName);

}
