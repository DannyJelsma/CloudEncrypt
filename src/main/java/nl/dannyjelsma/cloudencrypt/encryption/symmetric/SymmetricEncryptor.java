package nl.dannyjelsma.cloudencrypt.encryption.symmetric;

import com.goterl.lazysodium.interfaces.PwHash;
import com.goterl.lazysodium.interfaces.SecretStream;
import nl.dannyjelsma.cloudencrypt.CloudEncrypt;

import java.io.File;

public abstract class SymmetricEncryptor {

    public abstract byte[] encryptBytes(byte[] input, byte[] key);

    public byte[] encryptBytes(byte[] input, byte[] password, byte[] salt) {
        try {
            PwHash.Native pwHash = CloudEncrypt.getSodium();
            byte[] key = new byte[SecretStream.KEYBYTES];

            pwHash.cryptoPwHash(key, key.length, password, password.length, salt,
                    PwHash.ARGON2ID_OPSLIMIT_SENSITIVE, PwHash.MEMLIMIT_SENSITIVE, PwHash.Alg.PWHASH_ALG_ARGON2ID13);

            return encryptBytes(input, key);
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public abstract File encryptFile(File file, byte[] key);

}
