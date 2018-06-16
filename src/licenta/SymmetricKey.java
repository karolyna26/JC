package licenta;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricKey implements Criptable {

   private String algorithm;

   public String getAlgorithm() {
      return algorithm;
   }

   SecretKey key () throws NoSuchAlgorithmException  {
      KeyGenerator keygen = KeyGenerator.getInstance(getAlgorithm());
      SecureRandom secure = new SecureRandom ();

      //int [] keyBitsSize = {56, 128, 168, 256, 448};
      Map <String, Integer> key = new HashMap<>();
      key.put("DES", 56);
      key.put("RC2", 128);
      key.put("DESede", 168);
      key.put("AES", 256);

      for (Map.Entry m:key.entrySet()) {

         if (m.getKey().equals(getAlgorithm())) {
            int value = (int) m.getValue();
            keygen.init( value, secure);
         }

      }
      final SecretKey secretKey= keygen.generateKey();
      return secretKey;
   }


   public SymmetricKey() {
      // TODO Auto-generated constructor stub

   }
   public SymmetricKey (String algorithm) {
      this.algorithm = algorithm;
   }


   Key keySpecFile ( String key) throws NoSuchAlgorithmException  {
      Key keygen = null;
      List <String> keys = new ArrayList<>();
      keys.add("DES");
      keys.add("RC2");
      keys.add("DESede");
      keys.add("AES");

      for (String k: keys) {

         if (k==algorithm) {
            keygen = new SecretKeySpec(key.getBytes(), getAlgorithm() );
         }
      }

      return keygen;
   }


   Key keyImage () throws NoSuchAlgorithmException {
      KeyGenerator keygen = KeyGenerator.getInstance(getAlgorithm());
      Key key = keygen.generateKey();

      return key;

   }

   @Override
   public String toString() {
      return "SymmetricKey{" +
              "algorithm='" + algorithm + '\'' +
              '}';
   }
}
