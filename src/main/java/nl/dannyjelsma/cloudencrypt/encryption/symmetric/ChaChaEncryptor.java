package nl.dannyjelsma.cloudencrypt.encryption.symmetric;

import com.goterl.lazysodium.interfaces.SecretStream;
import nl.dannyjelsma.cloudencrypt.CloudEncrypt;

import java.io.*;
import java.util.Arrays;

public class ChaChaEncryptor extends SymmetricEncryptor {

    private static final int CHUNK_SIZE = 1048576;

    @Override
    public byte[] encryptBytes(byte[] input, byte[] key) {
        try {
            SecretStream.Native secretStream = CloudEncrypt.getSodium();
            SecretStream.State state = new SecretStream.State();
            byte[] header = new byte[SecretStream.HEADERBYTES];
            byte[] out = new byte[SecretStream.ABYTES + input.length];

            if (!secretStream.cryptoSecretStreamInitPush(state, header, key)) {
                System.out.println("Could not initialize ChaCha20!");
                return null;
            }

            if (!secretStream.cryptoSecretStreamPush(state, out, input, input.length, SecretStream.TAG_FINAL)) {
                System.out.println("Failed to encrypt buffer with ChaCha20!");
                return null;
            }

            ByteArrayOutputStream bos = new ByteArrayOutputStream(header.length + out.length);
            bos.write(header);
            bos.write(out);
            byte[] result = bos.toByteArray();
            bos.close();

            return result;
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    @Override
    public File encryptFile(File file, byte[] key) {
        try {
            SecretStream.Native secretStream = CloudEncrypt.getSodium();
            SecretStream.State state = new SecretStream.State();
            byte[] header = new byte[SecretStream.HEADERBYTES];
            byte[] bufIn = new byte[CHUNK_SIZE];
            byte[] bufOut = new byte[SecretStream.ABYTES + CHUNK_SIZE];
            File tempFile = new File(file.getParentFile(), file.getName() + ".ce");

            if (!tempFile.exists()) {
                tempFile.createNewFile();
            }

            if (!secretStream.cryptoSecretStreamInitPush(state, header, key)) {
                System.out.println("Could not initialize ChaCha20!");
                return null;
            }

            try (BufferedInputStream fis = new BufferedInputStream(new FileInputStream(file), CHUNK_SIZE * 4);
                 BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(tempFile, true), CHUNK_SIZE * 8)) {
                out.write(header);

                int read;
                int totalRead = 0;
                while ((read = fis.read(bufIn)) > 0) {
                    totalRead += read;
                    byte tag = totalRead >= file.length() ? 0 : SecretStream.TAG_FINAL;

                    if (read < CHUNK_SIZE) {
                        bufIn = Arrays.copyOf(bufIn, read);
                        bufOut = new byte[SecretStream.ABYTES + read];
                    }

                    if (!secretStream.cryptoSecretStreamPush(state, bufOut, bufIn, bufIn.length, tag)) {
                        System.out.println("Failed to encrypt buffer with ChaCha20!");
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
