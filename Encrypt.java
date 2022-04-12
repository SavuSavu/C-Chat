import android.annotation.SuppressLint;
import android.annotation.TargetApi;
import android.provider.SyncStateContract;
import android.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

// Some of the code in this class is inspired by the tutorial: 
// https://www.amarinfotech.com/how-to-do-aes-256-encryption-decryption-in-android.html

class Encrypt {
    public static String[] EncryptData(String text) throws Exception {
        // this is the key generator that needs to know what type of random key to generate
        KeyGenerator keyGen = KeyGenerator.getInstance("AES"); 
        // setting the encryption bytes  
        keyGen.init(256); 
        SecretKey secretKey = keyGen.generateKey();
    
        // setting up the type of encryption  
        Cipher cipher = Cipher.getInstance("AES");
        // encrypting the message
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        //storing encrypted message as bytes 
        byte[] results = cipher.doFinal(text.getBytes());
        // converting the key to Base64 format to be able to send it over internet 
        String stringKey = Base64.encodeToString(secretKey.getEncoded(), Base64.DEFAULT);
        
        //Change result to Base64
        String SResult = Base64.encodeToString(results, Base64.NO_WRAP|Base64.DEFAULT);
       
        String[] MessageAndKey = new String[2];
        MessageAndKey[0]=SResult;
        MessageAndKey[1]=stringKey;
        return MessageAndKey;
    }
    
    public static String DecryptData(String text,  String key)throws Exception{
        //Changing the key from base64 to bytes
        byte[] encodedKey     = Base64.decode(key, Base64.DEFAULT);
        // converting the bytes key to object SecretKey
        SecretKey originalKey = new SecretKeySpec(encodedKey, 0, encodedKey.length, "AES");
        // change message from base64 to bytes
        byte[] encrypted_bytes = Base64.decode(text, Base64.DEFAULT);
        // setting up the type of decryption
        Cipher cipher = Cipher.getInstance("AES");
        // initializing the decryption  
        cipher.init(Cipher.DECRYPT_MODE, originalKey);
        // storing the decrypted message in bytes
        byte[] decrypted = cipher.doFinal(encrypted_bytes);
        String result = new String(decrypted);

    
        return result;
    }
}