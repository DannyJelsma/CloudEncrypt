package nl.dannyjelsma.cloudencrypt.decryption.asymmetric;

import com.goterl.lazysodium.interfaces.Box;
import nl.dannyjelsma.cloudencrypt.CloudEncrypt;

public class ECCDecryptor extends ASymmetricEncryptor {

    @Override
    public byte[] decryptBytes(byte[] input, byte[] publicKey, byte[] privateKey) {
        try {
            Box.Native cryptoBox = CloudEncrypt.getSodium();
            byte[] output = new byte[input.length - Box.SEALBYTES];

            if (!cryptoBox.cryptoBoxSealOpen(output, input, input.length, publicKey, privateKey)) {
                System.out.println("Error decrypting bytes with ECC!");
                return null;
            }

            return output;
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }
}
