package nl.dannyjelsma.cloudencrypt.download;

import nl.dannyjelsma.cloudencrypt.backup.BackupFolder;
import nl.dannyjelsma.cloudencrypt.decryption.AESDecryptor;
import nl.dannyjelsma.cloudencrypt.decryption.RSADecryptor;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.PublicKey;
import java.util.Base64;
import java.util.List;
import java.util.regex.Pattern;

public class OneDriveDownloader implements Downloader {

    @Override
    public String getName() {
        return null;
    }

    @Override
    public List<File> downloadFiles(BackupFolder folder) {
        return null;
    }
}
