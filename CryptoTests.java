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
	Security.addProvider(new BouncyCastleProvider());
	Scanner keyboard = new Scanner(System.in);
	System.out.print("Would you like to run a performance test? (y/n): ");
			   
	String resp = keyboard.nextLine();
	if(resp.equals("y")) {
	    System.out.println("Running performance tests...");
	    System.out.println("Computing encryption/decryption of 100 random 32 char Strings...\n");
	    String[] randStrings = getRandStrings(100, 32);
	    System.out.print("Using 128-bit AES...");
	    long deltaAES = System.currentTimeMillis();
	    for(String rand : randStrings) testAES(rand, false);
	    deltaAES = System.currentTimeMillis() - deltaAES;
	    System.out.println("Done!");
	    System.out.print("Using 128-bit Blowfish...");
	    long deltaBlowfish = System.currentTimeMillis();
	    for(String rand : randStrings) testBlowfish(rand, false);
	    deltaBlowfish = System.currentTimeMillis() - deltaBlowfish;
	    System.out.println("Done!");
	    System.out.print("Using 1024-bit RSA...");
	    long deltaRSA = System.currentTimeMillis();
	    for(String rand : randStrings) testRSA(rand, false);
	    deltaRSA = System.currentTimeMillis() - deltaRSA;
	    System.out.println("Done!\n");

	    System.out.println("---Results---");
	    System.out.printf("AES was %.2f times faster than RSA\n", (float)deltaRSA/deltaAES);
	    System.out.printf("Blowfish was %.2f times faster than RSA\n", 
			      (float)deltaRSA/deltaBlowfish);
	    System.out.printf("Blowfish was %.2f times faster than AES\n", 
			      (float)deltaAES/deltaBlowfish);
	} else {
	    System.out.println("Please enter the string you would like to encrypt");
	    String msg = keyboard.nextLine();
	    System.out.println("---AES---");
	    testAES(msg, true);
	    System.out.println("---Blowfish---");
	    testBlowfish(msg, true);
	    System.out.println("---RSA---");
	    testRSA(msg, true);
	    System.out.println("---RSA Signature---");
	    signRSA(msg, true);
	}
    }
    public static void testAES(String msg, boolean printOut) {
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
	    if(printOut) {
		System.out.println("Decrypted Plaintext: " + new String(plaintext));
	    }
	} catch (Exception e) {
	    System.err.print("In decryption: ");
	    System.err.println(e);
	    System.exit(1);
	}

    }
    public static void testBlowfish(String msg, boolean printOut) {
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
	    if(printOut) {
		System.out.println("Decrypted Plaintext: " + new String(plaintext));
	    }
	} catch (Exception e) {
	    System.err.print("In decryption: ");
	    System.err.println(e);
	    System.exit(1);
	}
    }
    public static void testRSA(String msg, boolean printOut) {
	KeyPairGenerator keyPairGen = null;
	KeyPair pair = null;
	Cipher cipher = null;
	byte[] ciphertext = null;
	byte[] plaintext = null;
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
	    if(printOut) {
		System.out.println("Decrypted Plaintext: " + new String(plaintext));
	    }
	} catch (Exception e) {
	    System.err.print("In encrypt/decrypt: ");
	    System.err.println(e);
	    System.exit(1);
	}
    }
    public static void signRSA(String msg, boolean printOut) {
	KeyPairGenerator keyPairGen = null;
	KeyPair pair = null;
	Signature sign = null;
	byte[] signature = null;
	//generate RSA signature over msg
	try {
	    keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
	    keyPairGen.initialize(1024, new SecureRandom());
	
	    pair = keyPairGen.generateKeyPair();
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
	    if(sign.verify(signature) && printOut) {
		System.out.println("Verified RSA signature!");
	    } else if (printOut) {
		System.out.println("Failed to verify RSA signature.");
	    }
	} catch (Exception e) {
	    System.err.print("In signature verification: ");
	    System.err.println(e);
	    System.exit(1);
	}
    }
    public static String[] getRandStrings(int numStrings, int length) {
	String[] randStrings = new String[numStrings];
	Random rand = new Random();
	for(int i = 0; i < numStrings; i++) {
	    String randChars = "";
	    for(int j = 0; j < length; j++) {
		randChars += (char)(rand.nextInt(127-32) + 32);
	    }
	    randStrings[i] = randChars;
	}
	return randStrings;
    }
}
