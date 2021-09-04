package nl.dannyjelsma.cloudencrypt;

import nl.dannyjelsma.cloudencrypt.backup.BackupFolder;
import nl.dannyjelsma.cloudencrypt.backup.BackupManager;
import nl.dannyjelsma.cloudencrypt.download.LocalTestDownloader;
import nl.dannyjelsma.cloudencrypt.upload.LocalTestUploader;

import java.io.File;

public class CloudEncrypt {

    /*public static void main(String[] args) {
        AESEncryptor encryptor = new AESEncryptor();
        AESDecryptor decryptor = new AESDecryptor();
        byte[] password = new byte[128];

        try {
            SecureRandom.getInstanceStrong().nextBytes(password);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        System.out.println("Using the following password: " + new String(password));
        System.out.println("Encryping test file...");
        long start = System.currentTimeMillis();
        byte[] encryptedFile = encryptor.encryptFileContents(new File("C:\\Users\\Danny\\Desktop\\coins.json"),
                new String(password));
        try {
            Files.write(Path.of("C:\\Users\\Danny\\Desktop\\coins-test1.json"), encryptedFile, StandardOpenOption.CREATE);
        } catch (IOException e) {
            e.printStackTrace();
        }

        long end = System.currentTimeMillis() - start;
        System.out.println("Took " + end + "ms");

        System.out.println("Decrypting test file...");
        start = System.currentTimeMillis();
        byte[] decryptedFile = decryptor.decryptFileContents(new File("C:\\Users\\Danny\\Desktop\\coins-test1.json"),
                new String(password));
        try {
            Files.write(Path.of("C:\\Users\\Danny\\Desktop\\coins-test2.json"), decryptedFile, StandardOpenOption.CREATE);
        } catch (IOException e) {
            e.printStackTrace();
        }

        end = System.currentTimeMillis() - start;
        System.out.println("Took " + end + "ms");
    }*/

    public static void main(String[] args) {
        BackupFolder folder = new BackupFolder(new File("C:\\Users\\Danny\\Desktop\\backup-folder-test"));
        BackupManager backupManager = new BackupManager(folder, "#*^JTKLW4JbFq*L%o%S2%Q4Ra", false);

        backupManager.uploadBackup(new LocalTestUploader());
        //backupManager.downloadBackup(new LocalTestDownloader());
    }
}
