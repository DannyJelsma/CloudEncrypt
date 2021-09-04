package nl.dannyjelsma.cloudencrypt.backup;

import nl.dannyjelsma.cloudencrypt.decryption.AESDecryptor;
import nl.dannyjelsma.cloudencrypt.download.Downloader;
import nl.dannyjelsma.cloudencrypt.encryption.AESEncryptor;
import nl.dannyjelsma.cloudencrypt.encryption.RSAEncryptor;
import nl.dannyjelsma.cloudencrypt.exceptions.BackupNotInitializedException;
import nl.dannyjelsma.cloudencrypt.upload.Uploader;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class BackupManager {

    private final BackupFolder backupFolder;
    private final String password;
    private PublicKey publicKey;
    private PrivateKey privateKey;
    private SecureRandom random;
    private boolean encryptFileNames;

    public BackupManager(BackupFolder folder, String password, boolean encryptFileNames) {
        this.backupFolder = folder;
        this.password = password;
        this.encryptFileNames = encryptFileNames;

        try {
            this.random = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

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
            AESEncryptor encryptor = new AESEncryptor();
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(4096, random);
            KeyPair pair = generator.generateKeyPair();
            PrivateKey privateKey = pair.getPrivate();
            PublicKey publicKey = pair.getPublic();

            File privateKeyFile = new File(backupFolder.getFolder(), "ce_priv.key");
            File publicKeyFile = new File(backupFolder.getFolder(), "ce_pub.key");
            Files.write(privateKeyFile.toPath(), privateKey.getEncoded(), StandardOpenOption.CREATE);
            Files.write(publicKeyFile.toPath(), publicKey.getEncoded(), StandardOpenOption.CREATE);

            byte[] encryptedPrivKey = encryptor.encryptFileContents(privateKeyFile, password.getBytes());
            Files.write(privateKeyFile.toPath(), encryptedPrivKey, StandardOpenOption.WRITE, StandardOpenOption.TRUNCATE_EXISTING);

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

        File publicKeyFile = backupFolder.getPublicKey();
        File privateKeyFile = backupFolder.getPrivateKey();
        AESDecryptor decryptor = new AESDecryptor();

        try {
            byte[] decryptedPubKey = Files.readAllBytes(publicKeyFile.toPath());
            byte[] decryptedPrivKey = decryptor.decryptFileContents(privateKeyFile, password.getBytes());
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decryptedPubKey);
            EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(decryptedPrivKey);

            publicKey = keyFactory.generatePublic(publicKeySpec);
            privateKey = keyFactory.generatePrivate(privateKeySpec);
            return true;
        } catch (Exception ex) {
            ex.printStackTrace();
            return false;
        }
    }

    public void uploadBackup(Uploader uploader) {
        File[] files = backupFolder.getFolder().listFiles();
        AESEncryptor aesEncryptor = new AESEncryptor();
        RSAEncryptor rsaEncryptor = new RSAEncryptor();

        if (files == null) return;

        for (File file : files) {
            if (file.getName().equals("ce_priv.key") || file.getName().equals("ce_pub.key")) continue;

            System.out.println("Encrypting " + file.getName() + "...");
            long start = System.currentTimeMillis();
            try {
                byte[] password = new byte[128];
                random.nextBytes(password);

                byte[] encryptedBytes = aesEncryptor.encryptFileContents(file, password);
                byte[] encryptedPassword = Base64.getEncoder().encode(rsaEncryptor.encryptBytes(password, publicKey));

                ByteArrayOutputStream os = new ByteArrayOutputStream();
                os.writeBytes(encryptedBytes);
                os.writeBytes("$CEPS$".getBytes());
                os.write(encryptedPassword);

                byte[] fileBytes = os.toByteArray();
                long end = System.currentTimeMillis() - start;
                System.out.println("Encryption took " + end + "ms");

                start = System.currentTimeMillis();
                uploader.uploadFile(fileBytes, file.getName());
                end = System.currentTimeMillis() - start;
                System.out.println("Uploading took " + end + "ms");
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    public void downloadBackup(Downloader downloader) {

    }
}
