package nl.dannyjelsma.cloudencrypt.decryption;

import de.mkammerer.argon2.Argon2Advanced;
import de.mkammerer.argon2.Argon2Factory;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Base64;
import java.util.regex.Pattern;

public class AESDecryptor {

    public String decryptString(String input, byte[] password, byte[] salt, byte[] iv) {
        return new String(decryptBytes(input.getBytes(), password, salt, iv));
    }

    public byte[] decryptBytes(byte[] input, byte[] password, byte[] salt, byte[] iv) {
        try {
            Argon2Advanced argon2 = Argon2Factory.createAdvanced(Argon2Factory.Argon2Types.ARGON2id);
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            byte[] key = argon2.pbkdf(5, 1<<15, 4, password, salt, 32);
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            return cipher.doFinal(input);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public byte[] decryptBytes(byte[] input, byte[] key, byte[] iv) {
        try {
            IvParameterSpec ivSpec = new IvParameterSpec(iv);
            SecretKeySpec secretKey = new SecretKeySpec(key, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");

            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
            return cipher.doFinal(input);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public byte[] decryptFileContents(File file, byte[] password) {
        try (FileInputStream fis = new FileInputStream(file)) {
            String encrypted = new String(Files.readAllBytes(file.toPath()));
            String[] encryptionInfo = encrypted.split(Pattern.quote("$CEST$"))[1].split(Pattern.quote("$CEIV$"));
            int encryptionInfoSize;

            if (encrypted.contains("$CEPS$")) {
                encryptionInfo[1] = encryptionInfo[1].split(Pattern.quote("$CEPS$"))[0];
            }

            encryptionInfoSize = encrypted.split(Pattern.quote("$CEST$"))[1].getBytes().length + "$CEST$".getBytes().length;
            byte[] decoded = fis.readNBytes(((int) file.length()) - encryptionInfoSize);
            byte[] salt = Base64.getDecoder().decode(encryptionInfo[0]);
            byte[] iv = Base64.getDecoder().decode(encryptionInfo[1]);

            return decryptBytes(decoded, password, salt, iv);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return null;
    }
}
