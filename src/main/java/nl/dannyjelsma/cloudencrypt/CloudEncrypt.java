package nl.dannyjelsma.cloudencrypt;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.SodiumJava;
import nl.dannyjelsma.cloudencrypt.backup.BackupFolder;
import nl.dannyjelsma.cloudencrypt.backup.BackupManager;
import nl.dannyjelsma.cloudencrypt.download.DropboxDownloader;
import nl.dannyjelsma.cloudencrypt.download.LocalTestDownloader;
import nl.dannyjelsma.cloudencrypt.encryption.EncryptionAlgorithm;
import nl.dannyjelsma.cloudencrypt.upload.DropboxUploader;
import nl.dannyjelsma.cloudencrypt.upload.LocalTestUploader;

import java.io.File;
import java.nio.charset.StandardCharsets;

public class CloudEncrypt {

    private static LazySodiumJava sodium;

    public static void main(String[] args) {
        try {
            sodium = new LazySodiumJava(new SodiumJava(), StandardCharsets.UTF_8);
            sodium.sodiumInit();

            BackupFolder folder = new BackupFolder(new File("D:\\backup"), "#*^JTKLW4JbFq*L%o%S2%Q4Ra", EncryptionAlgorithm.AES_GCM);
            BackupManager backupManager = new BackupManager(folder, true, true);

            //backupManager.uploadBackup(new LocalTestUploader());
            //backupManager.downloadBackup(new LocalTestDownloader());

            //backupManager.uploadBackup(new DropboxUploader());
            //backupManager.downloadBackup(new DropboxDownloader());
        } catch (Exception ex) {
            ex.printStackTrace();
        }
    }

    public static LazySodiumJava getSodium() {
        return sodium;
    }
}
