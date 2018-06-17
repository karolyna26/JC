package licenta;

import java.io.Closeable;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricCrypto extends Symmetric {
   private static Cipher cipher;
   private String plainText;
   private byte[] textToEncrypt = null;
   private String algorithm;
   private static final SecureRandom random = new SecureRandom();
   private SecretKey secretKey;
   private IvParameterSpec iv;
   private Key keyImag;
   private Key keySpecFile;

   /*
    * public void setAlgorithm (String algorithm) { this.algorithm = algorithm; }
    */
   public String getAlgorithm() {
      return algorithm;
   }

   public void setPlainText(String plainText) {
      this.plainText = plainText;
   }

   public String getPlainText() {

      return plainText;
   }

   public byte[] getTextToEncrypt() throws UnsupportedEncodingException {

      return textToEncrypt = this.getPlainText().getBytes("UTF8");
   }

   IvParameterSpec getIV () {
      final byte[] ivBytes = new byte[cipher.getBlockSize()];

      random.nextBytes(ivBytes);
      return new IvParameterSpec(ivBytes);
   }
   public SymmetricCrypto() {
   }

   public SymmetricCrypto(String algorithm) throws NoSuchPaddingException, NoSuchAlgorithmException {
      this.algorithm = algorithm;
      this.cipher = Cipher.getInstance(algorithm);
   }

   public SymmetricCrypto(String plainText, String algorithm) {
      this.plainText = plainText;
      this.algorithm = algorithm;
   }

   static byte[] encryptText(byte[] textToEncrypt, SecretKey secretKey, IvParameterSpec iv)
           throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

      cipher.init(Cipher.ENCRYPT_MODE, secretKey, iv, random);
      byte[] encryptedBytes = cipher.doFinal(textToEncrypt);
      return encryptedBytes;
   }
    public String encryptText(String msg, String algorithm) throws UnsupportedEncodingException, BadPaddingException, IllegalBlockSizeException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {

            cipher.init(Cipher.ENCRYPT_MODE, getSecretKey(algorithm), getIV(), random);
            return new String(org.apache.commons.codec.binary.Base64.encodeBase64(cipher.doFinal(msg.getBytes("UTF-8"))));
    }

   static byte[] decryptedText(byte[] encryptedBytes, SecretKey secretKey, IvParameterSpec iv)
           throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {

      cipher.init(Cipher.DECRYPT_MODE, secretKey, iv, random);
      byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
      return decryptedBytes;

   }

    public String decryptText(String msg, String algorithm) throws BadPaddingException, IllegalBlockSizeException, UnsupportedEncodingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException {

            this.cipher.init(Cipher.DECRYPT_MODE, getSecretKey(algorithm), getIV(), random);


            return new String(cipher.doFinal(org.apache.commons.codec.binary.Base64.decodeBase64(msg.getBytes())), "UTF-8");

    }

   static void encryptFile(Key key, File inputFile, File outputFile, IvParameterSpec iv) {
      FileInputStream inputStream = null;
      FileOutputStream outputStream = null;
      try {
         cipher.init(Cipher.ENCRYPT_MODE, key, iv, random);

         inputStream = new FileInputStream(inputFile);
         byte[] inputBytes = new byte[(int) inputFile.length()];
         inputStream.read(inputBytes);
         byte[] outputBytes = cipher.doFinal(inputBytes);
         outputStream = new FileOutputStream(outputFile);
         outputStream.write(outputBytes);

      } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | IOException e1) {
         // TODO Auto-generated catch block
         e1.printStackTrace();
      } catch (InvalidAlgorithmParameterException e) {
         // TODO Auto-generated catch block
         e.printStackTrace();
      } finally {

         closeQuietly(inputStream, outputStream);

      }

   }

   static void decryptedFile(Key key, File inputFile, File outputFile, IvParameterSpec iv) {
      FileInputStream inputStream = null;
      FileOutputStream outputStream = null;
      try {
         cipher.init(Cipher.DECRYPT_MODE, key, iv, random);

         inputStream = new FileInputStream(inputFile);
         byte[] inputBytes = new byte[(int) inputFile.length()];
         inputStream.read(inputBytes);
         byte[] outputBytes = cipher.doFinal(inputBytes);
         outputStream = new FileOutputStream(outputFile);
         outputStream.write(outputBytes);

      } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeyException | IOException e1) {
         // TODO Auto-generated catch block
         e1.printStackTrace();
      } catch (InvalidAlgorithmParameterException e) {
         // TODO Auto-generated catch block
         e.printStackTrace();
      } finally {

         closeQuietly(inputStream, outputStream);

      }
   }

   static void encryptImage(Key key, File inputFile, File outputFile, IvParameterSpec iv) {
      CipherOutputStream cos = null;
      FileOutputStream fos = null;
      FileInputStream fis = null;

      int i;
      try {

         cipher.init(Cipher.ENCRYPT_MODE, key, iv, random);
         fis = new FileInputStream(inputFile);
         fos = new FileOutputStream(outputFile);
         cos = new CipherOutputStream(fos, cipher);// SymmetricCrypto.cipherAlgorithm(algorithm));
         byte[] buff = new byte[1024];
         while ((i = fis.read(buff)) != -1) {
            fos.write(buff);
         }
      } catch (InvalidKeyException | IOException // NoSuchPaddingException | NoSuchAlgorithmException
              e) {
         // TODO Auto-generated catch block
         e.printStackTrace();
      } catch (InvalidAlgorithmParameterException e) {
         e.printStackTrace();
      }
   }

   static void decryptImage(Key key, File inputFile, File outputFile, IvParameterSpec iv) {
      CipherOutputStream cos = null;
      FileOutputStream fos = null;
      FileInputStream fis = null;
      int i;
      try {

         cipher.init(Cipher.DECRYPT_MODE, key, iv, random);
         fis = new FileInputStream(inputFile);
         fos = new FileOutputStream(outputFile);
         cos = new CipherOutputStream(fos, cipher);
         byte[] buff = new byte[1024];
         while ((i = fis.read(buff)) != -1) {
            fos.write(buff);
         }
      } catch (InvalidKeyException | IOException e) {
         // TODO Auto-generated catch block
         e.printStackTrace();
      } catch (InvalidAlgorithmParameterException e) {
         e.printStackTrace();
      }



   }

   @Override
   public String encryptTime(long executionTime) {

      return String.valueOf(executionTime);

   }

   @Override
   public String decpryptTime(long executionTime) {

      return String.valueOf(executionTime);
   }

   static void closeQuietly(Closeable... close) {
      for (Closeable c : close) {
         if (c != null) {
            try {
               c.close();
            } catch (IOException e) {
               e.printStackTrace();
            }
         }
      }
   }
   public byte[] getFileInBytes(File f) throws IOException {
      FileInputStream fis = new FileInputStream(f);
      byte[] fbytes = new byte[(int) f.length()];
      fis.read(fbytes);
      fis.close();
      return fbytes;
   }

   private void write(File file, byte[] outputToWrite) throws IOException {
      FileOutputStream fos = new FileOutputStream(file);
      fos.write(outputToWrite);
      if (fos != null)
         fos.close();
   }

   public SecretKey getSecretKey (String algorithm) throws NoSuchAlgorithmException {
      if (secretKey == null) {
         secretKey = new SymmetricKey(algorithm).key();
      }
      return secretKey;
   }

   public  IvParameterSpec getSymmetricCryptoIV() {
      if (iv == null) {
         iv = getIV();
      }
      return iv;
   }

   public Key getkeyImag (String algorithm) throws NoSuchAlgorithmException {
      if (keyImag == null) {
         keyImag = new SymmetricKey(algorithm).keyImage();
      }
      return keyImag;
   }

   public Key getKeySpecFile ( String key, String algorithm) throws NoSuchAlgorithmException {
      if (keySpecFile == null) {
         System.out.println("1");
         keySpecFile = new SymmetricKey(algorithm).keySpecFile( key);
         System.out.println("keySpecFile="+keySpecFile);

      }
      return keySpecFile;
   }

    @Override
    public String toString() {
        return "SymmetricCrypto{" +
                "plainText='" + plainText + '\'' +
                ", textToEncrypt=" + Arrays.toString(textToEncrypt) +
                ", algorithm='" + algorithm + '\'' +
                ", secretKey=" + secretKey +
                ", iv=" + iv +
                ", keyImag=" + keyImag +
                ", keySpecFile=" + keySpecFile +
                '}';
    }
}
