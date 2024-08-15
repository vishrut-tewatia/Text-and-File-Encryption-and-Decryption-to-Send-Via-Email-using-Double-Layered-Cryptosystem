import java.security.*;
import java.security.spec.*;
import java.io.*;
import javax.crypto.Cipher;
public class RSAText {

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
   /* public static void main(String args[]) throws Exception{
      RSAText rsa = new RSAText();
      rsa.generatekey();
      PublicKey a = rsa.rsapublic();
      PrivateKey b = rsa.rsaprivate();
      rsa.storekeys();
      String haha = rsa.encryption("Himanshu\nSingh\nYadav");
      String gaga = rsa.decryption("/Users/kapildevsingh/Desktop/BTPnew/RSAcipher", "/Users/kapildevsingh/Desktop/BTPnew/RSAprivate");
   }*/

    
   public void storekeys() throws Exception{
      dir = System.getProperty("user.dir");
      //Saving keys in files
      byte[] pubkey = this.pubk.getEncoded();
      FileOutputStream keyfos = new FileOutputStream(dir+"/TextRSApublic");
      keyfos.write(pubkey);
      keyfos.close();


      byte[] privkey = this.privk.getEncoded();
      FileOutputStream kyfos = new FileOutputStream( dir +"/TextRSAprivate");
      kyfos.write(privkey);
      kyfos.close();

   }
   public String encryption (String message) throws Exception{
      //Creating a Cipher object
      Cipher cipher = Cipher.getInstance("RSA");
        
      //Initializing a Cipher object
      cipher.init(Cipher.ENCRYPT_MODE,this.pubk);
	  
      //Adding data to the cipher
      byte[] input = message.getBytes();	  
      cipher.update(input);
	  
      //encrypting the data
      byte[] cipherText = cipher.doFinal();

      FileOutputStream cipherfos = new FileOutputStream(dir+"/TextRSAcipher");
      cipherfos.write(cipherText);
      cipherfos.close();
      String encryptmsg = this.display(cipherText);
      System.out.println("\nEncryption is :\n\n" + encryptmsg + "\n");
      return encryptmsg;

   }

   public String decryption (String message ,String cipherpath , String keypath) throws Exception {
      //accessing keys
      FileInputStream keyfis = new FileInputStream(keypath);
      FileInputStream cipherfis = new FileInputStream(cipherpath);

      //cipher byte
      byte[] ciphert = new byte[cipherfis.available()];
      cipherfis.read(ciphert);
      cipherfis.close();

      //checking if same or not 
      String ciphertext = this.display(ciphert);
      if(!message.equals(ciphertext)){
        return "Sytem Error: \nCipher Text and Cipher File not same";
      }

      //key
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
      byte[] decipheredText = cipher.doFinal(ciphert);
      String decryptmsg = new String(decipheredText);
      System.out.println("\nDecryption is :\n\n" + decryptmsg + "\n");
      return decryptmsg;

   }

   public static String display(byte[] b1) {
      StringBuilder strBuilder = new StringBuilder();
      for(byte val : b1) {
         strBuilder.append(String.format("%02x", val&0xff));
      }
      return strBuilder.toString();
   }
}