// Amirali Sanatinia amirali@ccs.neu.edu
// Network Security JCE demo

import javax.crypto.*;
import java.security.*;
import java.security.spec.*;
import java.io.*;

public class Encrypt {

	public static void main(String[] args) throws Exception {

		String public_key_filename, private_key_filename, plaintext_file;
		
		// Public, private and signature instances
		Cipher publicChiper = Cipher.getInstance("RSA");
		Cipher secCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		Signature sig = Signature.getInstance("SHA512withRSA");
		KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
		Key aesKey;
		PKCS8EncodedKeySpec privateSpec;
		X509EncodedKeySpec publicSpec;
		PrivateKey prvKey;
		PublicKey pubKey;
		
		// byte representation of parameters and IV
		byte[] iv, cipherText, publicKey, plainText, privateKey, signature, aesKeyEncyrpted;

		// Encrypting files
			public_key_filename = args[1];
			private_key_filename = args[2];
			plaintext_file = args[3];
		
		
		
	
			// Symmetric (AES) key generation
			KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
			aesKey = aesKeyGen.generateKey();
			// read bytes from the file
			plainText = readByteFromFile(new File(plaintext_file));
			// setup IV key with random data and encrypt the file using AES key.
			secCipher.init(Cipher.ENCRYPT_MODE, aesKey);
			iv = secCipher.getIV();
			cipherText = secCipher.doFinal(plainText);
			
			privateKey = readByteFromFile(new File(private_key_filename));
			publicKey = readByteFromFile(new File(public_key_filename));
			privateSpec = new PKCS8EncodedKeySpec(privateKey);
			publicSpec = new X509EncodedKeySpec(publicKey);
			prvKey = rsaKeyFactory.generatePrivate(privateSpec);
			pubKey = rsaKeyFactory.generatePublic(publicSpec);

			publicChiper.init(Cipher.WRAP_MODE, pubKey);
			aesKeyEncyrpted = publicChiper.wrap(aesKey);

			sig.initSign(prvKey);
			sig.update(iv);
			sig.update(cipherText);
			sig.update(aesKeyEncyrpted);
			signature = sig.sign();
			
			
			for (byte b : signature){
				System.out.print(String.format("%02X ", b));
			}
			System.out.println();
			System.out.println();
			for (byte b : cipherText){
				System.out.print(String.format("%02X ", b));
			}
			System.out.println();

	}


	// read bytes from a file
	private static byte[] readByteFromFile(File f) throws Exception {

		if (f.length() > Integer.MAX_VALUE)
			System.out.println("File is too large");

		byte[] buffer = new byte[(int) f.length()];
		InputStream ios = new FileInputStream(f);;
		DataInputStream dis = new DataInputStream(ios);
		dis.readFully(buffer);
		dis.close();
		ios.close();

		return buffer;
	}
}