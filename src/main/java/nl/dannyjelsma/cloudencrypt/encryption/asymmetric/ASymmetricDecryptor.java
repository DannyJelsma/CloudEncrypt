package nl.dannyjelsma.cloudencrypt.encryption.asymmetric;

public abstract class ASymmetricDecryptor {

    public abstract byte[] encryptBytes(byte[] input, byte[] publicKey);

}
