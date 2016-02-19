import org.bouncycastle.jce.provider.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
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
	System.out.println("---RSA---");
	testRSA(msg);
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
    public static void testRSA(String msg) {
	KeyPairGenerator keyPairGen = null;
	KeyPair pair = null;
	Cipher cipher = null;
	byte[] ciphertext = null;
	byte[] plaintext = null;
	Signature sign = null;
	byte[] signature = null;
	//Generate keypair
	try {
	    keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
	    keyPairGen.initialize(1024, new SecureRandom());
	
	    pair = keyPairGen.generateKeyPair();
	    cipher = Cipher.getInstance("RSA/NONE/OAEPWithSHA256AndMGF1Padding", "BC");
	    cipher.init(Cipher.ENCRYPT_MODE, pair.getPublic());
	} catch (Exception e) {
	    System.err.print("In key generation: ");
	    System.err.println(e);
	    System.exit(1);
	}
	//encrypt msg
	try {   
	    ciphertext = cipher.doFinal(msg.getBytes());
	    //decrypt ciphertext
	    cipher.init(Cipher.DECRYPT_MODE, pair.getPrivate());
	    plaintext = cipher.doFinal(ciphertext);
	    System.out.println("Decrypted Plaintext: " + new String(plaintext));
	} catch (Exception e) {
	    System.err.print("In encrypt/decrypt: ");
	    System.err.println(e);
	    System.exit(1);
	}
	//generate RSA signature over msg
	try {
	System.out.println("Signing message...");
	sign = Signature.getInstance("SHA256withRSA", "BC");
	sign.initSign(pair.getPrivate());

	sign.update(msg.getBytes());
	signature = sign.sign();
	} catch (Exception e) {
	    System.err.print("In RSA signing: ");
	    System.err.println(e);
	    System.exit(1);
	}
	//verify signature, print verified
	try {
	    sign.initVerify(pair.getPublic());
	    sign.update(msg.getBytes());
	    if(sign.verify(signature)) {
		System.out.println("Verified RSA signature!");
	    } else {
		System.out.println("Failed to verify RSA signature.");
	    }
	} catch (Exception e) {
	    System.err.print("In signature verification: ");
	    System.err.println(e);
	    System.exit(1);
	}
    }
}
