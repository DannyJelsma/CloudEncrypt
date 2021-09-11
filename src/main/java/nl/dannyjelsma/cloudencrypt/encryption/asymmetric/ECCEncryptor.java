package nl.dannyjelsma.cloudencrypt.encryption.asymmetric;

import com.goterl.lazysodium.interfaces.Box;
import nl.dannyjelsma.cloudencrypt.CloudEncrypt;

public class ECCEncryptor {

    public byte[] encryptBytes(byte[] input, byte[] publicKey) {
        Box.Native cryptoBox = CloudEncrypt.getSodium();
        byte[] output = new byte[Box.SEALBYTES + input.length];

        if (!cryptoBox.cryptoBoxSeal(output, input, input.length, publicKey)) {
            System.out.println("Error encrypting bytes with ECC!");
            return null;
        }

        return output;
    }
}
