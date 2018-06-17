package licenta;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class AsymmetricCrypto extends Asymmetric {
   private Cipher cipher;
   // private AsymmetricKey ak;
   private String algorithm;
   private String plainText;
   private PrivateKey privateKey;
   private PublicKey publicKey;

   public AsymmetricCrypto(String algorithm) throws Exception {
      this.algorithm = algorithm;
      try {
         this.cipher = Cipher.getInstance(algorithm);
      } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
         // TODO Auto-generated catch block
         e.printStackTrace();
      }
      privateKey = getPrivateKey("KeyPair/privateKey");
      publicKey = getPublicKey("KeyPair/publicKey");
   }

   public AsymmetricCrypto(String algorithm, String plainText) throws Exception {
      this.algorithm = algorithm;
      this.plainText = plainText;
      privateKey = getPrivateKey("KeyPair/privateKey");
      publicKey = getPublicKey("KeyPair/publicKey");
   }

   public AsymmetricCrypto() {

   }

   public void setPlainText(String plainText) {
      this.plainText = plainText;

   }

   public String getPlainText() {
      return plainText;
   }

   public String getAlgorithm() {
      return algorithm;
   }

   // Using: RSA = 2048, DSA = 3072, ECC = 224
   // https://docs.oracle.com/javase/8/docs/api/java/security/spec/PKCS8EncodedKeySpec.html
   public PrivateKey getPrivateKey(String filename) throws Exception {
      byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
      KeyFactory kf = KeyFactory.getInstance(algorithm);
      PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
      return kf.generatePrivate(spec);
   }

   // https://docs.oracle.com/javase/8/docs/api/java/security/spec/X509EncodedKeySpec.html
   public PublicKey getPublicKey(String filename) throws Exception {
      byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
      KeyFactory kf = KeyFactory.getInstance(algorithm);
      X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
      return kf.generatePublic(spec);
   }

   public void encryptFile(byte[] input, File output) throws IOException, GeneralSecurityException {
      this.cipher.init(Cipher.ENCRYPT_MODE, privateKey);
      writeToFile(output, this.cipher.doFinal(input));

   }

   public void decryptFile(byte[] input, File output) throws IOException, GeneralSecurityException {
      this.cipher.init(Cipher.DECRYPT_MODE, publicKey);
      writeToFile(output, this.cipher.doFinal(input));
   }

   private void writeToFile(File output, byte[] toWrite)
         throws IllegalBlockSizeException, BadPaddingException, IOException {
      FileOutputStream fos = new FileOutputStream(output);
      fos.write(toWrite);
      fos.flush();
      fos.close();
   }

   public String encryptText(String msg) throws NoSuchAlgorithmException, NoSuchPaddingException,
         UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException {
      this.cipher.init(Cipher.ENCRYPT_MODE, privateKey);
      return new String(org.apache.commons.codec.binary.Base64.encodeBase64(cipher.doFinal(msg.getBytes("UTF-8"))));
   }

   public String decryptText(String msg)
         throws InvalidKeyException, UnsupportedEncodingException, IllegalBlockSizeException, BadPaddingException {
      this.cipher.init(Cipher.DECRYPT_MODE, publicKey);
      return new String(cipher.doFinal(org.apache.commons.codec.binary.Base64.decodeBase64(msg.getBytes())), "UTF-8");
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

    @Override
    public String toString() {
        return "AsymmetricCrypto{" +
                "algorithm='" + algorithm + '\'' +
                ", plainText='" + plainText + '\'' +
                ", privateKey=" + privateKey +
                ", publicKey=" + publicKey +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        AsymmetricCrypto that = (AsymmetricCrypto) o;
        return Objects.equals(cipher, that.cipher) &&
                Objects.equals(algorithm, that.algorithm) &&
                Objects.equals(plainText, that.plainText) &&
                Objects.equals(privateKey, that.privateKey) &&
                Objects.equals(publicKey, that.publicKey);
    }

    @Override
    public int hashCode() {

        return Objects.hash(cipher, algorithm, plainText, privateKey, publicKey);
    }
}
