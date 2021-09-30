package nl.dannyjelsma.cloudencrypt.encryption.symmetric;

import com.goterl.lazysodium.LazySodiumJava;
import com.goterl.lazysodium.interfaces.AEAD;
import nl.dannyjelsma.cloudencrypt.CloudEncrypt;

import java.io.*;
import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class AESEncryptor extends SymmetricEncryptor {

    private static final int CHUNK_SIZE = 1048576;

    @Override
    public byte[] encryptBytes(byte[] input, byte[] key) {
        SecureRandom random;
        try {
            random = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return new byte[0];
        }

        AEAD.Native aead = CloudEncrypt.getSodium();
        byte[] bufOut = new byte[AEAD.AES256GCM_ABYTES + input.length];
        byte[] nonce = new byte[AEAD.AES256GCM_NPUBBYTES];
        ByteArrayOutputStream bos = new ByteArrayOutputStream(nonce.length + bufOut.length);

        random.nextBytes(nonce);
        bos.writeBytes(nonce);
        aead.cryptoAeadAES256GCMEncrypt(bufOut, new long[]{bufOut.length}, input, input.length, null, 0, null, nonce, key);
        bos.writeBytes(bufOut);
        byte[] result = bos.toByteArray();

        try {
            bos.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return result;
    }

    public File encryptFile(File file, byte[] key) {
        try {
            SecureRandom random = SecureRandom.getInstanceStrong();
            AEAD.Native aead = CloudEncrypt.getSodium();
            byte[] bufIn = new byte[CHUNK_SIZE];
            byte[] bufOut = new byte[AEAD.AES256GCM_ABYTES + CHUNK_SIZE];
            byte[] nonce = new byte[AEAD.AES256GCM_NPUBBYTES];
            File tempFile = new File(file.getParentFile(), file.getName() + ".ce");

            random.nextBytes(nonce);

            if (!tempFile.exists()) {
                tempFile.createNewFile();
            }

            try (BufferedInputStream fis = new BufferedInputStream(new FileInputStream(file), CHUNK_SIZE * 4);
                 BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(tempFile, true), CHUNK_SIZE * 8)) {
                out.write(nonce);

                int read;
                while ((read = fis.read(bufIn)) > 0) {
                    if (read < CHUNK_SIZE) {
                        bufIn = Arrays.copyOf(bufIn, read);
                        bufOut = new byte[AEAD.AES256GCM_ABYTES + read];
                    }

                    aead.cryptoAeadAES256GCMEncrypt(bufOut, new long[]{bufOut.length}, bufIn, bufIn.length, null, 0, null, nonce, key);
                    out.write(bufOut);

                    // The nonce should be incremented after every chunk.
                    long longNonce = bytesToLong(nonce);
                    longNonce += 1;
                    nonce = longToBytes(longNonce);
                }
            }

            return tempFile;
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public byte[] longToBytes(long x) {
        ByteBuffer buffer = ByteBuffer.allocate(AEAD.AES256GCM_NPUBBYTES);
        buffer.putLong(x);
        return buffer.array();
    }

    public long bytesToLong(byte[] bytes) {
        ByteBuffer buffer = ByteBuffer.allocate(AEAD.AES256GCM_NPUBBYTES);
        buffer.put(bytes);
        buffer.flip();
        return buffer.getLong();
    }
}
