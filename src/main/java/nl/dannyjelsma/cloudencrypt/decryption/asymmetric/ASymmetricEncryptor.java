package nl.dannyjelsma.cloudencrypt.decryption.asymmetric;

public abstract class ASymmetricEncryptor {

    public abstract byte[] decryptBytes(byte[] input, byte[] publicKey, byte[] privateKey);

}
