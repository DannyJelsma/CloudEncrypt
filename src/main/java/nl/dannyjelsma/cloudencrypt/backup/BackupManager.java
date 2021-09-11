package nl.dannyjelsma.cloudencrypt.backup;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.interfaces.Box;
import com.goterl.lazysodium.interfaces.SecretStream;
import nl.dannyjelsma.cloudencrypt.CloudEncrypt;
import nl.dannyjelsma.cloudencrypt.decryption.asymmetric.ECCDecryptor;
import nl.dannyjelsma.cloudencrypt.decryption.symmetric.AESDecryptor;
import nl.dannyjelsma.cloudencrypt.decryption.symmetric.ChaChaDecryptor;
import nl.dannyjelsma.cloudencrypt.decryption.symmetric.SymmetricDecryptor;
import nl.dannyjelsma.cloudencrypt.download.Downloader;
import nl.dannyjelsma.cloudencrypt.encryption.EncryptionAlgorithm;
import nl.dannyjelsma.cloudencrypt.encryption.asymmetric.ECCEncryptor;
import nl.dannyjelsma.cloudencrypt.encryption.symmetric.AESEncryptor;
import nl.dannyjelsma.cloudencrypt.encryption.symmetric.ChaChaEncryptor;
import nl.dannyjelsma.cloudencrypt.encryption.symmetric.SymmetricEncryptor;
import nl.dannyjelsma.cloudencrypt.exceptions.BackupNotInitializedException;
import nl.dannyjelsma.cloudencrypt.upload.Uploader;
import org.apache.commons.io.FileUtils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.*;

public class BackupManager {

    private final BackupFolder backupFolder;
    private byte[] publicKey;
    private byte[] privateKey;
    private final boolean encryptFileNames;
    private final boolean encryptDirectoryNames;

    // TODO: encryptFileNames and encryptDirectoryNames to BackupFolder?
    public BackupManager(BackupFolder folder, boolean encryptFileNames, boolean encryptDirectoryNames) {
        this.backupFolder = folder;
        this.encryptFileNames = encryptFileNames;
        this.encryptDirectoryNames = encryptDirectoryNames;

        if (backupFolder.requiresFirstTimeInit()) {
            if (!doFirstTimeInit()) {
                System.out.println("Something went wrong!");
                System.exit(1);
            }
        }

        if (!loadKeypair()) {
            System.out.println("Something went wrong!");
            System.exit(1);
        }
    }

    public boolean doFirstTimeInit() {
        try {
            LazySodiumJava sodium = CloudEncrypt.getSodium();
            Box.Native cryptoBox = CloudEncrypt.getSodium();
            SymmetricEncryptor encryptor = backupFolder.getSymmetricEncryptor();
            byte[] publicKey = new byte[Box.PUBLICKEYBYTES];
            byte[] privateKey = new byte[Box.SECRETKEYBYTES];
            byte[] salt = sodium.randomBytesBuf(16);
            cryptoBox.cryptoBoxKeypair(publicKey, privateKey);

            byte[] encryptedPrivateKey = encryptor.encryptBytes(privateKey, sodium.bytes(backupFolder.getPassword()), salt);
            ByteArrayOutputStream bos = new ByteArrayOutputStream(encryptedPrivateKey.length + salt.length);
            bos.write(salt);
            bos.write(encryptedPrivateKey);
            byte[] finalPrivateKey = bos.toByteArray();
            bos.close();

            File privateKeyFile = new File(backupFolder.getFolder(), "ce_priv.key");
            File publicKeyFile = new File(backupFolder.getFolder(), "ce_pub.key");
            Files.write(privateKeyFile.toPath(), finalPrivateKey, StandardOpenOption.CREATE);
            Files.write(publicKeyFile.toPath(), publicKey, StandardOpenOption.CREATE);

            return true;
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }

    public boolean loadKeypair() {
        if (backupFolder.requiresFirstTimeInit()) {
            throw new BackupNotInitializedException();
        }

        LazySodiumJava sodium = CloudEncrypt.getSodium();
        File publicKeyFile = backupFolder.getPublicKey();
        File privateKeyFile = backupFolder.getPrivateKey();
        SymmetricDecryptor decryptor = backupFolder.getSymmetricDecryptor();

        try {
            FileInputStream fis = new FileInputStream(privateKeyFile);
            byte[] salt = fis.readNBytes(16);
            byte[] privateKeyBytes = fis.readAllBytes();

            fis.close();
            this.publicKey = Files.readAllBytes(publicKeyFile.toPath());
            this.privateKey = decryptor.decryptBytes(privateKeyBytes, sodium.bytes(backupFolder.getPassword()), salt);
            return true;
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }

    public void uploadBackup(Uploader uploader) {
        LazySodiumJava sodium = CloudEncrypt.getSodium();
        Collection<File> files = FileUtils.listFiles(backupFolder.getFolder(), null, true);
        HashMap<String, String> directoryNameCache = new HashMap<>();
        SymmetricEncryptor encryptor = backupFolder.getSymmetricEncryptor();
        ECCEncryptor eccEncryptor = new ECCEncryptor();

        if (files == null) return;

        for (File file : files) {
            if (file.getName().equals("ce_priv.key") || file.getName().equals("ce_pub.key")
                    || file.getName().endsWith(".ce") || file.getName().equals("oauth.json")
                    || file.getName().endsWith(".cename")) continue;

            if (file.length() <= 0) continue;

            System.out.println("Encrypting " + file.getName() + "...");
            long start = System.currentTimeMillis();
            try {
                SecretStream.Native secretStream = CloudEncrypt.getSodium();
                byte[] password = new byte[SecretStream.KEYBYTES];
                secretStream.cryptoSecretStreamKeygen(password);
                byte[] encryptedPassword = eccEncryptor.encryptBytes(password, publicKey);
                File preEncryptionFile = new File(file.getParentFile(), file.getName() + ".ce");

                try (FileOutputStream fos = new FileOutputStream(preEncryptionFile)) {
                    fos.write(encryptedPassword);
                }

                File encryptedFile = encryptor.encryptFile(file, password);
                String dstPath = file.getAbsolutePath().replace(file.getName(), "")
                        .replace(backupFolder.getFolder().getAbsolutePath(), "") + file.getName();
                dstPath = dstPath.replace("\\", "/");

                if (encryptDirectoryNames) {
                    String[] split = dstPath.split("/");
                    List<File> nameFiles = new ArrayList<>();

                    for (int i = 1; i < split.length - 1; i++) {
                        String directoryName = split[i];
                        if (!directoryNameCache.containsKey(directoryName)) {
                            byte[] encryptedDirectoryNameBytes = eccEncryptor.encryptBytes(sodium.bytes(directoryName), publicKey);
                            String encryptedDirectoryName = Base64.getEncoder().encodeToString(encryptedDirectoryNameBytes);

                            if (encryptedDirectoryName.length() >= 200) {
                                System.out.println("Encrypted directory name too long! Using randomized name...");
                                String uuid = UUID.randomUUID().toString();
                                File nameFile = new File(encryptedFile.getParentFile(), uuid + ".cename");
                                Files.writeString(nameFile.toPath(), encryptedDirectoryName);
                                nameFiles.add(nameFile);
                                encryptedDirectoryName = uuid;
                            }

                            directoryNameCache.put(directoryName, encryptedDirectoryName.replace("/", "_"));
                            split[i] = encryptedDirectoryName.replace("/", "_");
                        } else {
                            split[i] = directoryNameCache.get(directoryName);
                        }
                    }

                    dstPath = String.join("/", split);

                    for (File nameFile : nameFiles) {
                        uploader.uploadFile(backupFolder, file, nameFile, dstPath.replace(file.getName(), nameFile.getName()));
                        nameFile.delete();
                    }
                }

                if (encryptFileNames) {
                    byte[] encryptedFileNameBytes = eccEncryptor.encryptBytes(sodium.bytes(file.getName()), publicKey);
                    String encryptedFileName = Base64.getEncoder().encodeToString(encryptedFileNameBytes);

                    if (encryptedFileName.length() >= 200) {
                        System.out.println("Encrypted file name too long! Using randomized name...");
                        String uuid = UUID.randomUUID().toString();
                        File nameFile = new File(encryptedFile.getParentFile(), uuid + ".cename");
                        Files.writeString(nameFile.toPath(), encryptedFileName);
                        uploader.uploadFile(backupFolder, file, nameFile, dstPath.replace(file.getName(), nameFile.getName()));
                        nameFile.delete();
                        encryptedFileName = uuid;
                    }

                    dstPath = dstPath.replace(file.getName(), encryptedFileName.replace("/", "_"));
                }

                long end = System.currentTimeMillis() - start;
                System.out.println("Encryption took " + end + "ms");
                start = System.currentTimeMillis();
                uploader.uploadFile(backupFolder, file, encryptedFile, dstPath);
                end = System.currentTimeMillis() - start;
                System.out.println("Uploading took " + end + "ms");
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    public void downloadBackup(Downloader downloader) {
        LazySodiumJava sodium = CloudEncrypt.getSodium();
        List<File> downloadedFiles = downloader.downloadFiles(backupFolder, -1);
        SymmetricDecryptor decryptor = backupFolder.getSymmetricDecryptor();
        ECCDecryptor eccDecryptor = new ECCDecryptor();

        for (File file : downloadedFiles) {
            long start = System.currentTimeMillis();

            if (file.getName().equals("ce_priv.key") || file.getName().equals("ce_pub.key")
                    || file.getName().endsWith(".ce") || file.getName().equals("oauth.json")
                    || file.getName().endsWith(".cename")) continue;

            try {
                System.out.println("Decrypting " + file.getName() + "...");
                FileInputStream fis = new FileInputStream(file);
                byte[] filePassword = new byte[Box.SEALBYTES + SecretStream.KEYBYTES];
                fis.read(filePassword);
                fis.close();
                byte[] decryptedPassword = eccDecryptor.decryptBytes(filePassword, publicKey, privateKey);
                File decryptedFile = decryptor.decryptFile(file, decryptedPassword, true);
                String dstPath = file.getAbsolutePath()
                        .replace(backupFolder.getFolder().getAbsolutePath(), "")
                        .replace("\\", "/");

                long end = System.currentTimeMillis() - start;
                System.out.println("Decryption took " + end + "ms");

                if (encryptDirectoryNames) {
                    String[] split = dstPath.split("/");
                    for (int i = 1; i < split.length - 1; i++) {
                        String directoryName = split[i];
                        byte[] decryptedDirectoryNameBytes;

                        if (directoryName.contains("-")) {
                            File nameFile = new File(file.getParentFile(), directoryName + ".cename");
                            decryptedDirectoryNameBytes = eccDecryptor.decryptBytes(Base64.getDecoder().decode(Files.readAllBytes(nameFile.toPath())), publicKey, privateKey);
                        } else {
                            decryptedDirectoryNameBytes = eccDecryptor.decryptBytes(Base64.getDecoder().decode(directoryName.replace("_", "/")), publicKey, privateKey);
                        }

                        String decryptedDirectoryName = sodium.str(decryptedDirectoryNameBytes);
                        split[i] = decryptedDirectoryName;
                    }

                    dstPath = String.join("/", split);
                }

                if (encryptFileNames) {
                    String encryptedFileName = file.getName().replace("_", "/");
                    byte[] decryptedFileNameBytes;

                    if (encryptedFileName.contains("-")) {
                        File nameFile = new File(file.getParentFile(), file.getName() + ".cename");
                        decryptedFileNameBytes = eccDecryptor.decryptBytes(Base64.getDecoder().decode(Files.readAllBytes(nameFile.toPath())), publicKey, privateKey);
                    } else {
                        decryptedFileNameBytes = eccDecryptor.decryptBytes(Base64.getDecoder().decode(encryptedFileName), publicKey, privateKey);
                    }

                    String decryptedFileName = sodium.str(decryptedFileNameBytes);
                    String[] split = dstPath.split("/");
                    dstPath = dstPath.replace(split[split.length - 1], decryptedFileName);
                }

                File dstFile = new File(backupFolder.getFolder(), dstPath);
                if (!dstFile.getParentFile().exists()) {
                    dstFile.getParentFile().mkdirs();
                }

                file.delete();
                Files.move(decryptedFile.toPath(), dstFile.toPath());
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }

        for (File file : downloadedFiles) {
            if (file.getParentFile().exists()) {
                deleteEmptyDirectories(file.getParentFile());
            }
        }
    }

    private void deleteEmptyDirectories(File file) {
        File[] files = file.listFiles();

        if (files != null) {
            for (File dirFile : files) {
                if (dirFile.isDirectory()) {
                    deleteEmptyDirectories(dirFile);
                    files = file.listFiles();
                } else if (dirFile.getName().endsWith(".cename")) {
                    dirFile.delete();
                }
            }
        }

        if (files.length == 0) {
            file.delete();
        }
    }
}
