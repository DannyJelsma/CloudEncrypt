package nl.dannyjelsma.cloudencrypt.encryption;

import de.mkammerer.argon2.Argon2Advanced;
import de.mkammerer.argon2.Argon2Factory;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class AESEncryptor {

    private SecureRandom random;

    public AESEncryptor() {
        try {
            this.random = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    public String encryptString(String input, byte[] password) {
        byte[] iv = new byte[16];
        byte[] salt = new byte[16];

        random.nextBytes(salt);
        random.nextBytes(iv);
        String base64 = Base64.getEncoder().encodeToString(encryptBytes(input.getBytes(), password, salt, iv));

        return base64 + "$CEST$" + Base64.getEncoder().encodeToString(salt) + "$CEIV$" + Base64.getEncoder().encodeToString(iv);
    }

    public byte[] encryptBytes(byte[] input, byte[] password, byte[] salt, byte[] iv) {
        try {
            Argon2Advanced argon2 = Argon2Factory.createAdvanced(Argon2Factory.Argon2Types.ARGON2id);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            byte[] key = argon2.pbkdf(4, 500000, 4, password, salt, 32);
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec, random);
            return cipher.doFinal(input);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public byte[] encryptFileContents(File file, byte[] password) {
        byte[] iv = new byte[16];
        byte[] salt = new byte[16];

        random.nextBytes(salt);
        random.nextBytes(iv);

        try {
            byte[] fileBytes = Files.readAllBytes(file.toPath());
            byte[] encryptedBytes = encryptBytes(fileBytes, password, salt, iv);
            byte[] encodedSalt = Base64.getEncoder().encode(salt);
            byte[] encodedIV = Base64.getEncoder().encode(iv);

            ByteArrayOutputStream os = new ByteArrayOutputStream();
            os.writeBytes(encryptedBytes);
            os.writeBytes("$CEST$".getBytes());
            os.writeBytes(encodedSalt);
            os.writeBytes("$CEIV$".getBytes());
            os.writeBytes(encodedIV);

            return os.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }
}
