package nl.dannyjelsma.cloudencrypt.upload;

public interface Uploader {

    String getName();

    void uploadFile(byte[] fileBytes, String fileName);

}
