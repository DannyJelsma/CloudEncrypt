package nl.dannyjelsma.cloudencrypt.decryption.symmetric;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.interfaces.Box;
import com.goterl.lazysodium.interfaces.PwHash;
import com.goterl.lazysodium.interfaces.SecretStream;
import nl.dannyjelsma.cloudencrypt.CloudEncrypt;

import java.io.*;
import java.nio.file.Files;
import java.util.Arrays;
import java.util.regex.Pattern;

public class ChaChaDecryptor extends SymmetricDecryptor {

    private static final int CHUNK_SIZE = 1048576;

    public byte[] decryptBytes(byte[] input, byte[] password, byte[] salt) {
        try {
            PwHash.Native pwHash = CloudEncrypt.getSodium();
            byte[] key = new byte[SecretStream.KEYBYTES];

            pwHash.cryptoPwHash(key, key.length, password, password.length, salt,
                    PwHash.ARGON2ID_OPSLIMIT_SENSITIVE, PwHash.MEMLIMIT_SENSITIVE, PwHash.Alg.PWHASH_ALG_ARGON2ID13);

            return decryptBytes(input, key);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public byte[] decryptBytes(byte[] input, byte[] key) {
        try {
            SecretStream.Native secretStream = CloudEncrypt.getSodium();
            SecretStream.State state = new SecretStream.State();
            ByteArrayInputStream bis = new ByteArrayInputStream(input);
            byte[] header = bis.readNBytes(SecretStream.HEADERBYTES);
            input = bis.readAllBytes();
            byte[] out = new byte[input.length - SecretStream.ABYTES];

            if (!secretStream.cryptoSecretStreamInitPull(state, header, key)) {
                System.out.println("Could not initialize ChaCha20!");
                return null;
            }

            byte[] tag = new byte[1];

            if (!secretStream.cryptoSecretStreamPull(state, out, tag, input, input.length)) {
                System.out.println("ChaCha: Corrupt bytes!");
                return null;
            }

            return out;
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public File decryptFile(File file, byte[] key, boolean containsPassword) {
        try {
            SecretStream.Native secretStream = CloudEncrypt.getSodium();
            SecretStream.State state = new SecretStream.State();
            byte[] header = new byte[SecretStream.HEADERBYTES];
            byte[] bufIn = new byte[SecretStream.ABYTES + CHUNK_SIZE];
            byte[] bufOut = new byte[CHUNK_SIZE];
            File tempFile = new File(file.getParentFile(), file.getName() + ".ce");

            if (tempFile.exists()) {
                tempFile.delete();
            }

            tempFile.createNewFile();

            try (BufferedInputStream fis = new BufferedInputStream(new FileInputStream(file), CHUNK_SIZE * 4);
                 BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(tempFile), CHUNK_SIZE * 8)) {
                if (containsPassword) {
                    fis.skip(SecretStream.KEYBYTES + Box.SEALBYTES);
                }

                fis.read(header);

                if (!secretStream.cryptoSecretStreamInitPull(state, header, key)) {
                    System.out.println("ChaCha: Corrupt header!");
                    tempFile.delete();
                    return null;
                }

                int read;
                while ((read = fis.read(bufIn)) > 0) {
                    byte[] tag = new byte[1];

                    if (read < CHUNK_SIZE) {
                        bufIn = Arrays.copyOf(bufIn, read);
                        bufOut = new byte[read - SecretStream.ABYTES];
                    }

                    if (!secretStream.cryptoSecretStreamPull(state, bufOut, tag, bufIn, bufIn.length)) {
                        System.out.println("ChaCha: Corrupt file!");
                        tempFile.delete();
                        return null;
                    }

                    out.write(bufOut);
                }
            }

            return tempFile;
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }
}
