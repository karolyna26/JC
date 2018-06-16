/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package licenta;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

/**
 * @author Carolina
 */
/*public class CryptoTime implements Criptable {
    private AsymmetricCrypto ac1 = null;
    private SymmetricCrypto sc1 = null;
    private AsymmetricCrypto ac2 = null;
    private SymmetricCrypto sc2 = null;
    public CryptoTime(AsymmetricCrypto ac1, AsymmetricCrypto ac2) {
        this.ac1 = ac1;
        this.ac2 = ac2;
    }
    public CryptoTime(SymmetricCrypto sc1, SymmetricCrypto sc2) {
        this.sc1 = sc1;
        this.sc2 = sc2;
    }
   public CompareResult compareTextEncryption(String plaintext) {
        String result1 = "", result2 = "";
        long startTime = System.nanoTime();
        if (ac1 != null) {
            try {
                result1 = ac1.encryptText(plaintext);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            }
        } else {
            result1 = sc1.encryptText(plaintext);
        }
        long endTime = System.nanoTime();
        long duration1 = (endTime - startTime);
        startTime = System.nanoTime();
        if (ac1 != null) {
            try {
                result2 = ac2.encryptText(plaintext);
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            } catch (NoSuchPaddingException e) {
                e.printStackTrace();
            } catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            } catch (IllegalBlockSizeException e) {
                e.printStackTrace();
            } catch (BadPaddingException e) {
                e.printStackTrace();
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            }
        } else {
            result2 = sc2.encryptText(plaintext);
        }
        endTime = System.nanoTime();
        long duration2 = (endTime - startTime)/1000000;
        return new CompareResult(duration1, duration2, result1, result2);
    }
    public CompareResult compareTextDecryption(String plaintext1, String plaintext2) {
        String result1 = "", result2 = "";
        long startTime = System.nanoTime();
        if (ac1 != null) {
            result1 = ac1.decryptText(plaintext1);
        } else {
            result1 = sc1.decryptText(plaintext1);
        }
        long endTime = System.nanoTime();
        long duration1 = (endTime - startTime);
        startTime = System.nanoTime();
        if (ac1 != null) {
            result2 = ac2.decryptText(plaintext2);
        } else {
            result2 = sc2.decryptText(plaintext2);
        }
        endTime = System.nanoTime();
        long duration2 = (endTime - startTime)/1000000;
        return new CompareResult(duration1, duration2, result1, result2);
    }
    public void compareFileEncryption() {
    }
    public void compareFileDecryption() {
    }
    
}
     
}
*/
/* this is a TestECC class....
package licenta;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
public class TestECC {
   public static byte[] iv = new SecureRandom().generateSeed(16);
   public static void main(String[] args) {
      Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
      String plainText = "Look mah, I'm a message!";
      System.out.println("Original plaintext message: " + plainText);
      // Initialize two key pairs
      KeyPair keyPairA = generateECKeys();
      KeyPair keyPairB = generateECKeys();
      // Create two AES secret keys to encrypt/decrypt the message
      SecretKey secretKeyA = generateSharedSecret(keyPairA.getPrivate(), keyPairB.getPublic());
      SecretKey secretKeyB = generateSharedSecret(keyPairB.getPrivate(), keyPairA.getPublic());
      // Encrypt the message using 'secretKeyA'
      String cipherText = encryptString(secretKeyA, plainText);
      System.out.println("Encrypted cipher text: " + cipherText);
      // Decrypt the message using 'secretKeyB'
      String decryptedPlainText = decryptString(secretKeyB, cipherText);
      System.out.println("Decrypted cipher text: " + decryptedPlainText);
   }
   public static KeyPair generateECKeys() {
      try {
         ECNamedCurveParameterSpec parameterSpec = ECNamedCurveTable.getParameterSpec("brainpoolp256r1");
         KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDH", "BC");
         keyPairGenerator.initialize(parameterSpec);
         KeyPair keyPair = keyPairGenerator.generateKeyPair();
         return keyPair;
      } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | NoSuchProviderException e) {
         e.printStackTrace();
         return null;
      }
   }
   public static SecretKey generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) {
      try {
         KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH", "BC");
         keyAgreement.init(privateKey);
         keyAgreement.doPhase(publicKey, true);
         SecretKey key = keyAgreement.generateSecret("AES");
         return key;
      } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchProviderException e) {
         // TODO Auto-generated catch block         e.printStackTrace();
         return null;
      }
   }
   public static String encryptString(SecretKey key, String plainText) {
      try {
         IvParameterSpec ivSpec = new IvParameterSpec(iv);
         Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
         byte[] plainTextBytes = plainText.getBytes("UTF-8");
         byte[] cipherText;
         cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);
         cipherText = new byte[cipher.getOutputSize(plainTextBytes.length)];
         int encryptLength = cipher.update(plainTextBytes, 0, plainTextBytes.length, cipherText, 0);
         encryptLength += cipher.doFinal(cipherText, encryptLength);
         return bytesToHex(cipherText);
      } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException
            | InvalidAlgorithmParameterException | UnsupportedEncodingException | ShortBufferException
            | IllegalBlockSizeException | BadPaddingException e) {
         e.printStackTrace();
         return null;
      }
   }
   public static String decryptString(SecretKey key, String cipherText) {
      try {
         Key decryptionKey = new SecretKeySpec(key.getEncoded(), key.getAlgorithm());
         IvParameterSpec ivSpec = new IvParameterSpec(iv);
         Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");
         byte[] cipherTextBytes = hexToBytes(cipherText);
         byte[] plainText;
         cipher.init(Cipher.DECRYPT_MODE, decryptionKey, ivSpec);
         plainText = new byte[cipher.getOutputSize(cipherTextBytes.length)];
         int decryptLength = cipher.update(cipherTextBytes, 0, cipherTextBytes.length, plainText, 0);
         decryptLength += cipher.doFinal(plainText, decryptLength);
         return new String(plainText, "UTF-8");
      } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException | InvalidKeyException
            | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException
            | ShortBufferException | UnsupportedEncodingException e) {
         e.printStackTrace();
         return null;
      }
   }
   public static String bytesToHex(byte[] data, int length) {
      String digits = "0123456789ABCDEF";
      StringBuffer buffer = new StringBuffer();
      for (int i = 0; i != length; i++) {
         int v = data[i] & 0xff;
         buffer.append(digits.charAt(v >> 4));
         buffer.append(digits.charAt(v & 0xf));
      }
      return buffer.toString();
   }
   public static String bytesToHex(byte[] data) {
      return bytesToHex(data, data.length);
   }
   public static byte[] hexToBytes(String string) {
      int length = string.length();
      byte[] data = new byte[length / 2];
      for (int i = 0; i < length; i += 2) {
         data[i / 2] = (byte) ((Character.digit(string.charAt(i), 16) << 4)
               + Character.digit(string.charAt(i + 1), 16));
      }
      return data;
   }
}
*/
/*
    This is a testEcies class..
    package licenta;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import javax.crypto.Cipher;
import org.bouncycastle.asn1.ocsp.Signature;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.IEKeySpec;
import org.bouncycastle.jce.spec.IESParameterSpec;
public class Ecies {
   private SecureRandom random;
   private int keySize;
   private KeyPair akey;
   private KeyPair bkey;
   public static void main(String[] args) throws Exception {
      Ecies ecies = new Ecies();
      ecies.establishKeys("secp256r1");
      Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
      byte[] plaintext = "Mary had a litle lamb.".getBytes();
      println("plaintext.length: " + plaintext.length);
      byte[] encrypted = ecies.encrypt(plaintext);
      println("encrypted.length: " + encrypted.length);
      byte[] decrypted = ecies.decrypt(encrypted);
      println("decrypted.length: " + decrypted.length);
      println("new String(decrypted): " + new String(decrypted));
   }
   public static void println(String string) {
      System.out.println(string);
   }
   public Ecies() throws Exception {
      this.random = new SecureRandom();
   }
   public void establishKeys(String keysize) throws Exception {
      X9ECParameters ecP = CustomNamedCurves.getByName("curve25519");
      ECParameterSpec ecSpec=new ECParameterSpec(ecP.getCurve(), ecP.getG(),
              ecP.getN(), ecP.getH(), ecP.getSeed());
      ECGenParameterSpec ecGenSpec = new ECGenParameterSpec(keysize);
      KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
      keyGen.initialize(112);
      this.akey = keyGen.generateKeyPair();
      this.bkey = keyGen.generateKeyPair();
      this.keySize = Integer.valueOf((ecGenSpec.getName().substring(4, 7))).intValue();
   }
   public byte[] encrypt(byte[] plainText) throws Exception {
      // get ECIES cipher objects
      Cipher acipher = Cipher.getInstance("ECIES");
      // generate derivation and encoding vectors
      byte[] d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
      byte[] e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
      IESParameterSpec param = new IESParameterSpec(d, e, 256);
      // encrypt the plaintext using the public key
      acipher.init(Cipher.ENCRYPT_MODE, new IEKeySpec(akey.getPrivate(), bkey.getPublic()), param);
      return acipher.doFinal(plainText);
   }
   public byte[] decrypt(byte[] cipherText) throws Exception {
      // get ECIES cipher objects
      Cipher bcipher = Cipher.getInstance("ECIES");
      // generate derivation and encoding vectors
      byte[] d = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };
      byte[] e = new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 };
      IESParameterSpec param = new IESParameterSpec(d, e, 256);
      // decrypt the text using the private key
      bcipher.init(Cipher.DECRYPT_MODE, new IEKeySpec(bkey.getPrivate(), akey.getPublic()), param);
      return bcipher.doFinal(cipherText);
   }
   public byte[] sign(byte[] plainText) throws Exception {
      Signature sig = Signature.getInstance("SHA1WithECDSA");
      sig.initSign(akey.getPrivate());
      sig.update(plainText);
      return sig.sign();
   }
   public boolean verify(byte[] plainText, byte[] signature) throws Exception {
      Signature sig = Signature.getInstance("SHA1WithECDSA");
      sig.initVerify(akey.getPublic());
      sig.update(plainText);
      try {
         if (sig.verify(signature)) {
            return true;
         } else
            return false;
      } catch (SignatureException se) {
         System.out.println("Signature failed");
      }
      return false;
   }
   public int getKeySize() {
      return keySize;
   }
}
 */
