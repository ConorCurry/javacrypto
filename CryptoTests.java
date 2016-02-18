import org.bouncycastle.jce.provider.*
import javax.crypto.*

public Class CryptoTests {
    public static void main(String[] args) {
	Scanner keyboard = new Scanner();
	System.out.println("Please enter the string you would like to encrypt");
	String msg = keyboard.nextLine();
	Security.addProvider(new BouncyCastleProvider());
    }
    public void testAES(String msg) {
	Key key;
	KeyGenerator keyGen;
	Cipher cipher;
	String ciphertext, plaintext;

	//Generate 128 bit key
	try {
	    keyGen = KeyGenerator.getInstance("AES", "BC");
	    keyGen.init(128, new SecureRandom());

	    key = keyGen.generateKey();
	} catch (Exception e) {
	    System.err.println(e);
	    System.exit(1);
	}

	//encrypt msg
	try {
	    //use padding for AES CBC mode.
	    cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
	    cipher.init(Cipher.ENCRYPT_MODE, key);

	    ciphertext = String(cipher.doFinal(msg.getBytes()));
	    System.out.println("Encrypted Ciphertext: " + ciphertext);
	} catch (Exception e) {
	    System.err.println(e);
	    System.exit(1);
	}

	//decrypt ciphertext
	try {
	    cipher.init(Cipher.DECRYPT_MODE, key);
	    
	    plaintext = String(cipher.doFinal(msg.getBytes()));
	    System.out.println("Decrypted Plaintext: " + plaintext);
	} catch (Exception e) {
	    System.err.println(e);
	    System.exit(1);
	}
    }
    public void testBlowfish(String msg) {
	//Generate 128 bit key
	//encrypt msg
	//decrypt ciphertext
	//print plaintext
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
