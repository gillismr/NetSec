import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.io.*;


public class Fcrypt{
	
	// main takes the runtime parameters and passes them to one of the three other methods 
	// based on the 0th parameter. It converts the input Strings to Files and then reads byte[]s
	// from those files, then passing them to either an encrypt or decrypt method. There is also 
	// the generate/create key method for setting up 2 RSA key pairs in the first place
	public static void main(String[] args) {
		
		byte[] cipherText, publicKey, plainText, privateKey;
		
		String publicKeyFile;
		String privateKeyFile;
		String inputFile;
		String outputFile;
		
		String keyGenPriv1File;
		String keyGenPub1File;
		String keyGenPriv2File;
		String keyGenPub2File;
		
		try{
			if (! (args.length == 5)){
                throw new Exception("Wrong number of command options");
			}
            
			else if (!((args[0].equals("-e") || (args[0].equals("-d")) || (args[0].equals("-g"))))) {
            	throw new Exception("Unrecognized flag: " + args[0]);
            }
			
			// ENCRYPT MODE
			else if (args[0].equals("-e")){
        		
        		publicKeyFile = args[1]; // destination_public_key_filename 
            	privateKeyFile = args[2]; // sender_private_key_filename 
        		inputFile = args[3]; // input_plaintext_file 
            	outputFile = args[4]; // output_ciphertext_file
            	OutputStream os = new FileOutputStream(new File(outputFile));
            	
            	plainText = readByteFromFile(new File(inputFile));
        		publicKey = readByteFromFile(new File(publicKeyFile));
        		privateKey = readByteFromFile(new File(privateKeyFile));
    			encryptAndSign(publicKey, privateKey, plainText, os);
        		
            }
            
			// DECRYPT MODE
			else if (args[0].equals("-d")){
            	
            	publicKeyFile = args[1]; // destination_private_key_filename 
            	privateKeyFile = args[2]; // sender_public_key_filename 
            	inputFile = args[3]; // input_ciphertext_file 
            	outputFile = args[4]; // output_plaintext_file
            	PrintWriter out = new PrintWriter(new File(outputFile));
            	
            	cipherText = readByteFromFile(new File(inputFile));
        		privateKey = readByteFromFile(new File(privateKeyFile));
        		publicKey = readByteFromFile(new File(publicKeyFile));
        		verifyAndDecrypt(privateKey, publicKey, cipherText, out);
            }
            
			// GENERATE MODE
			else {
            	//Generate mode: Generate 2 keyPairs for our sender and receiver
            	
            	keyGenPub1File = args[1]; // destination_public_key_filename
            	keyGenPriv1File = args[2]; // destination_private_key_filename 
        		keyGenPub2File = args[3]; // sender_public_key_file
        		keyGenPriv2File = args[4]; // sender_private_key_filename
        		
        		writeKeyPair(keyGenPub1File, keyGenPriv1File);
        		writeKeyPair(keyGenPub2File, keyGenPriv2File);
        		
            }
        }
		catch (Exception e) {
            System.err.println("Error: " + e);
            System.exit(1);
        }
	}
	
	public static void encryptAndSign(byte[] publicKey, byte[] privateKey, byte[] plainText, OutputStream os) throws Exception{
		
		byte[] iv, cipherText, allOutput, signature, aesKeyEncrypted;
		
		// Generate a symmetric (AES) key 
		KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
		Key aesKey = aesKeyGen.generateKey();
		
		// Encrypt the plainText with AES and store the random IV it uses
		Cipher secCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		secCipher.init(Cipher.ENCRYPT_MODE, aesKey);
		iv = secCipher.getIV();
		cipherText = secCipher.doFinal(plainText);
		
		// Convert the given encoded key byte[]s back to Keys
		KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKey);
		X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKey);
		PrivateKey prvKey = rsaKeyFactory.generatePrivate(privateSpec);
		PublicKey pubKey = rsaKeyFactory.generatePublic(publicSpec);
		
		// Encrypt (wrap) the symmetric (AES) key using the recipient's public Key (RSA) 
		Cipher publicChiper = Cipher.getInstance("RSA");
		publicChiper.init(Cipher.WRAP_MODE, pubKey);
		aesKeyEncrypted = publicChiper.wrap(aesKey);
		
		// Sign the data to be sent using the sender's private Key
		// Include the IV and the encrypted symmetric key for later symmetric decryption
		Signature sig = Signature.getInstance("SHA512withRSA");
		sig.initSign(prvKey);
		sig.update(iv);
		sig.update(cipherText);
		sig.update(aesKeyEncrypted);
		signature = sig.sign();
		
		// Put all the data into 1 byte[]
		allOutput = concat(signature, (concat(iv, (concat(aesKeyEncrypted, cipherText)))));
		
		
		//Println()s for checking lengths so I could be sure where to divide allInput in decrypt
		System.out.println("Signature length: " + signature.length);
		// 128 bytes = 1024 bits!
		
		System.out.println("IV length: " + iv.length);
		// 16 bytes = 128 bits!
		
		System.out.println("AES Encrypted Key length: " + aesKeyEncrypted.length);
		// 128 bytes = 1024 bits
		
		System.out.println("Actual AES Key length: " + aesKey.getEncoded().length);
		// 16 bytes = 128 bits 
		
		System.out.println("Cipher text length: " + cipherText.length);
		System.out.println("Total length: " + allOutput.length);
		
		// Write all the data with the given output stream
		os.write(allOutput);
		os.close();
		System.out.println("Encryption complete.");
		
	}
	
	
	
	public static void verifyAndDecrypt(byte[] privateKey, byte[] publicKey, byte[] allInput, PrintWriter out) throws Exception{
		
		byte[] iv, cipherText, plainText, signature, aesKeyEncrypted;
		
		
		// Break up allInput into its constituent parts based on the knowledge of 
		// what standards were used to encrypt it and how long the sections are
		signature = Arrays.copyOfRange(allInput, 0, 128);
		iv = Arrays.copyOfRange(allInput, 128, 144);
		aesKeyEncrypted = Arrays.copyOfRange(allInput, 144, 272);
		cipherText = Arrays.copyOfRange(allInput, 272, (allInput.length));
				
		// Convert the given encoded key byte[]s back to Keys
		KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKey);
		X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(publicKey);
		PrivateKey prvKey = rsaKeyFactory.generatePrivate(privateSpec);
		PublicKey pubKey = rsaKeyFactory.generatePublic(publicSpec);
		
		// Set up a Signature class to verify the authenticity of the iv, cipherText, 
		// and wrapped aesKey with the sender's public key 
		Signature sig = Signature.getInstance("SHA512withRSA");
		sig.initVerify(pubKey);
		sig.update(iv);
		sig.update(cipherText);
		sig.update(aesKeyEncrypted);
		
		// Verify the signature of the above data
		if(sig.verify(signature)){
			
			// Unwrap the symmetric (AES) key using our private Key
			Cipher privateCipher = Cipher.getInstance("RSA");
			privateCipher.init(Cipher.UNWRAP_MODE, prvKey);
			Key aesKey = privateCipher.unwrap(aesKeyEncrypted, "AES", Cipher.SECRET_KEY);
			System.out.println("AES Key unwrapped!");
			
			// Decrypt the cipherText with the decrypted symmetric (AES) key
			Cipher secCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			secCipher.init(Cipher.DECRYPT_MODE, aesKey, new IvParameterSpec(iv));
			plainText = secCipher.doFinal(cipherText);
			
			// Convert the decrypted byte[] to a String and write it with the given PrintWriter
			String result = new String(plainText);			
			out.println(result);
		}
		
		else{
			//If verification failed...
			System.out.println("Authentication failed. Self-destruct sequence activated.");
			out.close();
			return;
		}
				
		out.close();
		System.out.println("Decryption complete.");
		
	}
	
	
	// read bytes from a file
	private static byte[] readByteFromFile(File f) throws Exception {

		if (f.length() > Integer.MAX_VALUE)
			System.out.println("File is too large");

		byte[] buffer = new byte[(int) f.length()];
		InputStream fis = new FileInputStream(f);;
		DataInputStream dis = new DataInputStream(fis);
		dis.readFully(buffer);
		dis.close();
		fis.close();
		
		return buffer;
	}
	
	// Given file names, generate encoded byte[]s for an RSA keyPair and write them to those files
	private static void writeKeyPair(String pubFile, String privFile) throws Exception{
		OutputStream pubOS = new FileOutputStream(new File(pubFile));
		OutputStream privOS = new FileOutputStream(new File(privFile));
		
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        KeyPair myKeys = keyGen.genKeyPair();
        pubOS.write(myKeys.getPublic().getEncoded());
        privOS.write(myKeys.getPrivate().getEncoded());
        pubOS.close();
        privOS.close();
		
	}
	
	// Concatenates 2 byte[]s
	// Taken from StackOverflow
	public static byte[] concat(byte[] first, byte[] rest) {
		   int firstLen = first.length;
		   int restLen = rest.length;
		   byte[] all = new byte[firstLen + restLen];
		   System.arraycopy(first, 0, all, 0, firstLen);
		   System.arraycopy(rest, 0, all, firstLen, restLen);
		   return all;
		}

}
