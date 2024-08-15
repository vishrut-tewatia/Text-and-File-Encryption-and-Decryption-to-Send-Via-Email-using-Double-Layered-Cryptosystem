import java.security.*;
import java.security.spec.*;
import java.io.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
public class RSAFile {

   private KeyPairGenerator keyPairGen=null;
   private KeyPair pair=null;
   private PrivateKey privk;
   private PublicKey pubk;
   private static String dir;


   public void generatekey(){

      //Creating KeyPair generator object
      try {
         this.keyPairGen = KeyPairGenerator.getInstance("RSA");
      } catch (NoSuchAlgorithmException e) {
         //TODO: handle exception
      }

      //Initializing the key pair generator
      this.keyPairGen.initialize(2048);
         
     //Generating the pair of keys
      this.pair = keyPairGen.generateKeyPair();
      this.privk = pair.getPrivate();
      this.pubk = pair.getPublic();
   }

   public PublicKey rsapublic(){
      System.out.println(this.pubk);
      return this.pubk;
   }

   public PrivateKey rsaprivate(){
      System.out.println(this.privk);
      return this.privk;
   }
   /*public static void main(String args[]) throws Exception{
      RSAFile rsa = new RSAFile();
      rsa.generatekey();
      PublicKey a = rsa.rsapublic();
      PrivateKey b = rsa.rsaprivate();
      rsa.storekeys();
      rsa.encryption("/Users/kapildevsingh/Desktop/aes.key");
      SecretKey c= rsa.decryption("/Users/kapildevsingh/Desktop/double/aesencrypted.key", "/Users/kapildevsingh/Desktop/double/RSAprivate");
   }*/

    
   public void storekeys() throws Exception{
      dir = System.getProperty("user.dir");
      //Saving keys in files
      byte[] pubkey = this.pubk.getEncoded();
      FileOutputStream keyfos = new FileOutputStream(dir+"/FileRSApublic");
      keyfos.write(pubkey);
      keyfos.close();


      byte[] privkey = this.privk.getEncoded();
      FileOutputStream kyfos = new FileOutputStream(dir+"/FileRSAprivate");
      kyfos.write(privkey);
      kyfos.close();

   }
   public void encryption (String path) throws Exception{
      //Creating a Cipher object
      Cipher cipher = Cipher.getInstance("RSA");
        
      //Initializing a Cipher object
      cipher.init(Cipher.ENCRYPT_MODE,this.pubk);
	  
      //Adding data to the cipher
      FileInputStream cipherfis = new FileInputStream(path);

      //read cipher byte
      byte[] input = new byte[cipherfis.available()];
      cipherfis.read(input);
      cipherfis.close();	  
      cipher.update(input);
	  
      //encrypting the data
      byte[] cipherText = cipher.doFinal();

      FileOutputStream cipherfos = new FileOutputStream(dir+"/Fileaesencrypted.key");
      cipherfos.write(cipherText);
      cipherfos.close();

   }

   public static SecretKey decryption (String cipherpath , String keypath) throws Exception {
      //accessing keys
      FileInputStream keyfis = new FileInputStream(keypath);
      FileInputStream cipherfis = new FileInputStream(cipherpath);

      //read cipher byte
      byte[] ciphert = new byte[cipherfis.available()];
      cipherfis.read(ciphert);
      cipherfis.close();

      //read key
      byte[] decKey = new byte[keyfis.available()];
      keyfis.read(decKey);
      keyfis.close();
      PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(decKey);

      KeyFactory keyFactory = KeyFactory.getInstance("RSA");
      PrivateKey privks = keyFactory.generatePrivate(privKeySpec);

      //Creating a Cipher object
      Cipher cipher = Cipher.getInstance("RSA"); 

      //Initializing the same cipher for decryption
      cipher.init(Cipher.DECRYPT_MODE, privks);
      
      //Decrypting the text
      byte[] decipheredkey = cipher.doFinal(ciphert);
      SecretKeySpec skey = new SecretKeySpec(decipheredkey, "AES");
      return skey;
      /*String keyFile = "/Users/kapildevsingh/Desktop/double/aesdecrypted.key";
        try (FileOutputStream out = new FileOutputStream(keyFile)) {
            byte[] keyb = key.getEncoded();
            out.write(keyb);
        }catch (Exception ekey) {
            //TODO: handle exception
        }*/

   }
}