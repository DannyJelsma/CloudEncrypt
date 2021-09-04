package nl.dannyjelsma.cloudencrypt.backup;

import de.mkammerer.argon2.Argon2Advanced;
import de.mkammerer.argon2.Argon2Factory;
import nl.dannyjelsma.cloudencrypt.decryption.AESDecryptor;
import nl.dannyjelsma.cloudencrypt.decryption.RSADecryptor;
import nl.dannyjelsma.cloudencrypt.download.Downloader;
import nl.dannyjelsma.cloudencrypt.encryption.AESEncryptor;
import nl.dannyjelsma.cloudencrypt.encryption.RSAEncryptor;
import nl.dannyjelsma.cloudencrypt.exceptions.BackupNotInitializedException;
import nl.dannyjelsma.cloudencrypt.upload.Uploader;
import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.io.FileUtils;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.regex.Pattern;

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
        Collection<File> files = FileUtils.listFiles(backupFolder.getFolder(), null, true);
        AESEncryptor aesEncryptor = new AESEncryptor();
        RSAEncryptor rsaEncryptor = new RSAEncryptor();
        Argon2Advanced argon2;
        byte[] iv = new byte[0];
        byte[] salt;
        byte[] key = new byte[0];

        if (files == null) return;

        if (encryptFileNames) {
            argon2 = Argon2Factory.createAdvanced(Argon2Factory.Argon2Types.ARGON2id);
            iv = Arrays.copyOfRange(privateKey.getEncoded(), 0, 16);
            salt = Arrays.copyOfRange(privateKey.getEncoded(), 16, 32);
            key = argon2.pbkdf(3, 500000, 4, password.getBytes(), salt, 32);
        }

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
                String fileName = file.getAbsolutePath()
                        .replace(file.getName(), "")
                        .replace(backupFolder.getFolder().getAbsolutePath(), "") + file.getName();

                if (encryptFileNames) {
                    byte[] encryptedFileNameBytes = aesEncryptor.encryptBytes(file.getName().getBytes(), key, iv);
                    String encryptedFileName = Hex.encodeHexString(encryptedFileNameBytes) + ".cen";

                    if (encryptedFileName.length() >= 255) {
                        System.out.println("Encrypted file name too long! Using original name...");
                        encryptedFileName = file.getName();
                    }

                    fileName = file.getAbsolutePath()
                            .replace(file.getName(), "")
                            .replace(backupFolder.getFolder().getAbsolutePath(), "") + encryptedFileName;
                }

                long end = System.currentTimeMillis() - start;
                System.out.println("Encryption took " + end + "ms");
                uploader.uploadFile(fileBytes, fileName);
            } catch (Exception ex) {
                ex.printStackTrace();
            }
        }
    }

    public void downloadBackup(Downloader downloader) {
        List<File> downloadedFiles = downloader.downloadFiles(backupFolder);
        AESDecryptor aesDecryptor = new AESDecryptor();
        RSADecryptor rsaDecryptor = new RSADecryptor();
        Argon2Advanced argon2;
        byte[] iv = new byte[0];
        byte[] salt;
        byte[] key = new byte[0];

        if (encryptFileNames) {
            argon2 = Argon2Factory.createAdvanced(Argon2Factory.Argon2Types.ARGON2id);
            iv = Arrays.copyOfRange(privateKey.getEncoded(), 0, 16);
            salt = Arrays.copyOfRange(privateKey.getEncoded(), 16, 32);
            key = argon2.pbkdf(3, 500000, 4, password.getBytes(), salt, 32);
        }

        for (File file : downloadedFiles) {
            long start = System.currentTimeMillis();

            try {
                System.out.println("Decrypting " + file.getName() + "...");
                String fileContents = new String(Files.readAllBytes(file.toPath()));
                String filePassword = fileContents.split(Pattern.quote("$CEPS$"))[1];
                byte[] decryptedPassword = rsaDecryptor.decryptBytes(Base64.getDecoder().decode(filePassword), privateKey);
                byte[] decryptedContents = aesDecryptor.decryptFileContents(file, decryptedPassword);

                long end = System.currentTimeMillis() - start;
                System.out.println("Decryption took " + end + "ms");
                Files.write(file.toPath(), decryptedContents);

                if (encryptFileNames) {
                    byte[] decryptedFileNameBytes = aesDecryptor.decryptBytes(Hex.decodeHex(file.getName().replace(".cen", "")), key, iv);
                    String decryptedFileName = new String(decryptedFileNameBytes);

                    if (decryptedFileName.length() >= 255) {
                        System.out.println("Encrypted file name too long! Using original name...");
                        decryptedFileName = file.getName();
                    }

                    Files.move(file.toPath(), new File(backupFolder.getFolder(), decryptedFileName).toPath());
                }
            } catch (IOException | DecoderException e) {
                e.printStackTrace();
            }
        }
    }
}
