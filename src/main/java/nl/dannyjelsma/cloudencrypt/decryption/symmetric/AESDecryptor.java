package nl.dannyjelsma.cloudencrypt.decryption.symmetric;

import com.goterl.lazysodium.interfaces.AEAD;
import com.goterl.lazysodium.interfaces.Box;
import nl.dannyjelsma.cloudencrypt.CloudEncrypt;

import java.io.*;
import java.nio.ByteBuffer;
import java.util.Arrays;

public class AESDecryptor extends SymmetricDecryptor {

    private static final int CHUNK_SIZE = 1048576;

    @Override
    public File decryptFile(File file, byte[] key, boolean containsPassword) {
        try {
            AEAD.Native aead = CloudEncrypt.getSodium();
            byte[] bufIn = new byte[AEAD.AES256GCM_ABYTES + CHUNK_SIZE];
            byte[] bufOut = new byte[CHUNK_SIZE];
            byte[] nonce = new byte[AEAD.AES256GCM_NPUBBYTES];
            File tempFile = new File(file.getParentFile(), file.getName() + ".ce");

            if (tempFile.exists()) {
                tempFile.delete();
            }

            tempFile.createNewFile();

            try (BufferedInputStream fis = new BufferedInputStream(new FileInputStream(file), CHUNK_SIZE * 4);
                 BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(tempFile), CHUNK_SIZE * 8)) {
                if (containsPassword) {
                    fis.skip(AEAD.AES256GCM_KEYBYTES + Box.SEALBYTES);
                }

                fis.read(nonce);

                int read;
                while ((read = fis.read(bufIn)) > 0) {
                    if (read < CHUNK_SIZE) {
                        bufIn = Arrays.copyOf(bufIn, read);
                        bufOut = new byte[read - AEAD.AES256GCM_ABYTES];
                    }

                    if (!aead.cryptoAeadAES256GCMDecrypt(bufOut, new long[]{bufOut.length}, null, bufIn,
                            bufIn.length, null, 0, nonce, key)) {
                        System.out.println("Corrupt file!");
                        tempFile.delete();
                        return null;
                    }

                    out.write(bufOut);

                    // The nonce should be increased after every chunk.
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

    @Override
    public byte[] decryptBytes(byte[] input, byte[] key) {
        try {
            AEAD.Native aead = CloudEncrypt.getSodium();
            byte[] nonce = new byte[AEAD.AES256GCM_NPUBBYTES];
            ByteArrayInputStream bis = new ByteArrayInputStream(input);
            bis.read(nonce);
            byte[] bufIn = bis.readAllBytes();
            byte[] bufOut = new byte[bufIn.length - AEAD.AES256GCM_ABYTES];
            bis.close();

            if (!aead.cryptoAeadAES256GCMDecrypt(bufOut, new long[1], null, bufIn,
                    bufIn.length, null, 0, nonce, key)) {
                System.out.println("AES: Corrupt bytes!");
                return null;
            }

            return bufOut;
        } catch (Exception ex) {
            ex.printStackTrace();
            return null;
        }
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
