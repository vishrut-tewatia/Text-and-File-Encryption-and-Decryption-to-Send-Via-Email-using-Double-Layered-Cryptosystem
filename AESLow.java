import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.BadPaddingException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class AESLow {
    private static String dir;

    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        dir = System.getProperty("user.dir");
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        SecretKey key = keyGenerator.generateKey();
        String keyFile = dir + "/Fileaes.key";
        try (FileOutputStream out = new FileOutputStream(keyFile)) {
            byte[] keyb = key.getEncoded();
            out.write(keyb);
        }catch (Exception ekey) {
            //TODO: handle exception
        }
        
        return key;
    }

    public static SecretKey getKeyFromPassword(String password, String salt)
        throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        KeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        return secret;
    }

    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        IvParameterSpec ivspec = new IvParameterSpec(iv);
        byte[] ivexport = ivspec.getIV();
        String ivFile = dir + "/Fileaes.IV";
        try (FileOutputStream out = new FileOutputStream(ivFile)) {
        out.write(ivexport);
        } catch (Exception eiv) {
            // TODO: handle exception
        }
        return ivspec;
    }

    public static void encryptFile(SecretKey key, IvParameterSpec iv,
        File inputFile, File outputFile) throws IOException, NoSuchPaddingException,
        NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
        BadPaddingException, IllegalBlockSizeException {
        
        
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);

        /*
        int read;
        CipherInputStream cis = new CipherInputStream(inputStream, cipher);
        while((read = cis.read())!=-1)
                {
                    outputStream.write((char)read);
                    outputStream.flush();
                }   
        outputStream.close();
        */

        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {
            outputStream.write(outputBytes);
        }
        inputStream.close();
        outputStream.close();
    }

    public static void decryptFile( SecretKey key, IvParameterSpec iv,
        File encryptedFile, File decryptedFile) throws IOException, NoSuchPaddingException,
        NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
        BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        FileInputStream inputStream = new FileInputStream(encryptedFile);
        FileOutputStream outputStream = new FileOutputStream(decryptedFile);
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] output = cipher.doFinal();
        if (output != null) {
            outputStream.write(output);
        }
        inputStream.close();
        outputStream.close();
    }

    /*public static void main(String args[]) throws Exception{
    AESLow aes = new AESLow();
    File toencrypt = new File("/Users/kapildevsingh/Desktop/pexels.jpg");
    File encrypted = new File("/Users/kapildevsingh/Desktop/encrypted.jpg");
    File decrypted = new File("/Users/kapildevsingh/Desktop/decrypt.jpg");
    SecretKey a = aes.generateKey(256);
    IvParameterSpec b = aes.generateIv();
    aes.encryptFile(a, b, toencrypt, encrypted);
    aes.decryptFile(a, b, encrypted, decrypted);
    }*/

}