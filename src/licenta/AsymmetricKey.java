package licenta;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;

public class AsymmetricKey implements Criptable {
   private KeyPairGenerator kpg;
   private KeyPair keyPair;
   private PrivateKey privateKey;
   private PublicKey publicKey;
   private int length;
   private String algorithm;

   public AsymmetricKey(String algorithm) {
      super();
      this.algorithm = algorithm;
   }

   // RSA = 2048, DSA = 3072, ECC = 224
   /*
    * public void generateKeys (int length, String algorithm) throws
    * NoSuchAlgorithmException { this.keygen =
    * KeyPairGenerator.getInstance(algorithm); SecureRandom secure = new
    * SecureRandom(); keygen.initialize(length, secure);
    * 
    * }
    */
   public void createKeys() {
      this.keyPair = this.kpg.generateKeyPair();
      this.privateKey = keyPair.getPrivate();
      this.publicKey = keyPair.getPublic();

   }

   public PrivateKey getPrivateKey() {
      return this.privateKey;
   }

   public PublicKey getPublicKey() {
      return this.publicKey;
   }

   public AsymmetricKey(int length, String algorithm) {
      // TODO Auto-generated constructor stub
      // java.security.Security.addProvider(new
      // org.bouncycastle.jce.provider.BouncyCastleProvider());
      try {
         this.kpg = KeyPairGenerator.getInstance(algorithm);
      } catch (NoSuchAlgorithmException e) {
         // TODO Auto-generated catch block
         e.printStackTrace();
      }
      SecureRandom secure = new SecureRandom();
      kpg.initialize(length, secure);
   }
   
   public AsymmetricKey() {
      // TODO Auto-generated constructor stub
   }

   public void writePublicKey(String path, byte[] publicKey) {

      try (FileOutputStream fos = new FileOutputStream(new File(path))) {
         fos.write(publicKey);
      } catch (FileNotFoundException e) {
         // TODO Auto-generated catch block
         e.printStackTrace();
      } catch (IOException e1) {
         // TODO Auto-generated catch block
         e1.printStackTrace();
      }

   }

   public void writePrivateKey(String path, byte[] privateKey) {

      try (FileOutputStream fos = new FileOutputStream(new File(path))) {
         fos.write(privateKey);
      } catch (FileNotFoundException e) {
         // TODO Auto-generated catch block
         e.printStackTrace();
      } catch (IOException e1) {
         // TODO Auto-generated catch block
         e1.printStackTrace();
      }

   }

   public void setLength(int length) {
      this.length = length;
   }

   public int getLength() {
      return this.length;
   }
   /*
    * public Map <String, Object> generateKeysAsDictionary() { Map <String, Object>
    * keys = new HashMap<>(); keys.put("public", this.getPublicKey());
    * keys.put("private", this.getPrivateKey()); return keys;
    * 
    * }
    */
}
