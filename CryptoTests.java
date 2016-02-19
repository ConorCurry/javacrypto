import org.bouncycastle.jce.provider.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.*;

public class CryptoTests {
    public static void main(String[] args) {
	Scanner keyboard = new Scanner(System.in);
	System.out.println("Please enter the string you would like to encrypt");
	String msg = keyboard.nextLine();
	Security.addProvider(new BouncyCastleProvider());
	System.out.println("---AES---");
	testAES(msg);
	System.out.println("---Blowfish---");
	testBlowfish(msg);
    }
    public static void testAES(String msg) {
	SecretKeySpec key = null;
	IvParameterSpec iv = null;
	KeyGenerator keyGen = null;
	Cipher cipher = null;
	byte[] ciphertext = null;
	byte[] plaintext = null;

	//Generate 128 bit key
	try { 
	    keyGen = KeyGenerator.getInstance("AES", "BC");
	    keyGen.init(128, new SecureRandom());

	    key = (SecretKeySpec)keyGen.generateKey(); 
	} catch (Exception e) {
	    System.err.print("In key generation: ");
	    System.err.println(e);
	    System.exit(1);
	}

	//encrypt msg
	try {
	    //use padding for AES CBC mode.
	    cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	    cipher.init(Cipher.ENCRYPT_MODE, key);
	    iv = new IvParameterSpec(cipher.getIV());

	    ciphertext = cipher.doFinal(msg.getBytes());
	    System.out.println("Encrypted Ciphertext: " + new String(ciphertext));
	} catch (Exception e) {
	    System.err.print("In encryption: ");
	    System.err.println(e);
	    System.exit(1);
	}

	//decrypt ciphertext
	try {
	    IvParameterSpec ivParameterSpec = new IvParameterSpec(key.getEncoded());
	    cipher.init(Cipher.DECRYPT_MODE, key, iv);
	    
	    plaintext = cipher.doFinal(ciphertext);
	    System.out.println("Decrypted Plaintext: " + new String(plaintext));
	} catch (Exception e) {
	    System.err.print("In decryption: ");
	    System.err.println(e);
	    System.exit(1);
	}

    }
    public static void testBlowfish(String msg) {
	SecretKeySpec key = null;
	IvParameterSpec iv = null;
	KeyGenerator keyGen = null;
	Cipher cipher = null;
	byte[] ciphertext = null;
	byte[] plaintext = null;

	//Generate 128 bit key
	try { 
	    keyGen = KeyGenerator.getInstance("Blowfish", "BC");
	    keyGen.init(128, new SecureRandom());

	    key = (SecretKeySpec)keyGen.generateKey(); 
	} catch (Exception e) {
	    System.err.print("In key generation: ");
	    System.err.println(e);
	    System.exit(1);
	}

	//encrypt msg
	try {
	    //use padding for AES CBC mode.
	    cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
	    cipher.init(Cipher.ENCRYPT_MODE, key);
	    iv = new IvParameterSpec(cipher.getIV());

	    ciphertext = cipher.doFinal(msg.getBytes());
	    System.out.println("Encrypted Ciphertext: " + new String(ciphertext));
	} catch (Exception e) {
	    System.err.print("In encryption: ");
	    System.err.println(e);
	    System.exit(1);
	}

	//decrypt ciphertext
	try {
	    IvParameterSpec ivParameterSpec = new IvParameterSpec(key.getEncoded());
	    cipher.init(Cipher.DECRYPT_MODE, key, iv);
	    
	    plaintext = cipher.doFinal(ciphertext);
	    System.out.println("Decrypted Plaintext: " + new String(plaintext));
	} catch (Exception e) {
	    System.err.print("In decryption: ");
	    System.err.println(e);
	    System.exit(1);
	}
    }
    public void testRSA(String msg) {
	//Generate keypair
	//encrypt msg
	//decrypt ciphertext
	//print plaintext
	//generate RSA signature over msg
	//verify signature, print verified
    }
}
