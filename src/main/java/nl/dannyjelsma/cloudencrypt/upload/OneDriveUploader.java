package nl.dannyjelsma.cloudencrypt.upload;

import nl.dannyjelsma.cloudencrypt.backup.BackupFolder;

import java.io.File;

public class OneDriveUploader implements Uploader {

    @Override
    public String getName() {
        return null;
    }

    @Override
    public void uploadFile(BackupFolder folder, File originalFile, File encryptedFile, String fileName) {

    }
}
