import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;

import javax.crypto.*;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class SIMClient{

	//Fields for server connection configuration
	Scanner sc;
	String serverIP;
	int serverPort;
	Socket server;
	
	//Server public key fields
	byte[] serverKeyBytes;
	KeyFactory rsaKeyFactory;
	X509EncodedKeySpec publicSpec;
	PublicKey serverKey;
	
	//Streams between this client and the server
	ObjectInputStream input;
	ObjectOutputStream output;
    
    //Login
    BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
    String name, password;
    
    //Credentials to server
    byte[] nonce1 = new byte[16]; // 16 bytes = 128 bits
    byte[] pwHash;
    byte[] sendData;
    byte[] encryptedSendData;
    
    //Cookie
    byte[] cookie = new byte[64];
    
    //The person we're talking to
    InetAddress recipientINA;
	String recipient;
    PrivateKey signatureKey;
	PublicKey verificationKey;
	byte[] ticketToB;
	
	//Connecting to them
	private Socket recipientSocket;
	private ServerSocket listening;
	ObjectInputStream inputB;
	ObjectOutputStream outputB;
	
	//DiffieHellman stuff
	BigInteger p = new BigInteger("105721529231725396278744238019721944883459258934172331899960783719893356089817034253461201515439737670361933937940217427577693473956344804895358846880822392696046488918274717636071583814523522759796204222618840365316653936434709172113382318497752088322889563530999616413642023504696663722814258660783284649709");
	BigInteger g = new BigInteger("62951193033649707239238510868644285309198569779488005138430533330591756100547054332779476210740737931462466271496214673336150099168994589303046765366535435267910408582532215038620252157609127503823477022010406010833479619195676348865393025560501628436016618301150440981638807075483419386887089022419473465714");
	int l = 1023;
	SecretKey perfectSecretKey;
	
	
	
	public SIMClient(){
		
		recipient = null;
		
		
		//Get configuration info, set up connection(socket) with server
    	connectToServer();
    	
    	//Get the server's public key
    	setServerKey();
    	
    	//Establish the I/O streams
    	setServerStreams();
    	
    	//Gather login info from user
    	setLoginInfo();
    	
    	//Prepare and send credentials to server (generate nonce, hash PW, encrypt with serverKey)
    	sendCredentials();
    	
    	//Echo the received cookie
    	echoCookie();
    	
    	//Talk to server, make sure we're logged in and good to go
    	serverWelcome();
    	
    	processCommand();
    	
    	
	}
	
	public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException {
    	
		@SuppressWarnings("unused")
		SIMClient thisClient = new SIMClient();
		
    }
	
	private void connectToServer(){
		try {
			sc = new Scanner(new File("config.txt"));
			serverIP = sc.next();
			serverPort = Integer.parseInt(sc.next());
			server = new Socket(serverIP, serverPort);}
		catch (Exception e) {
			System.out.println(e);}
		System.out.println("Server config info found, connection established.");
	}
	
	private void setServerKey(){
		try {
			serverKeyBytes = readByteFromFile(new File("pub1.class"));
			rsaKeyFactory = KeyFactory.getInstance("RSA");
			publicSpec = new X509EncodedKeySpec(serverKeyBytes);
			serverKey = rsaKeyFactory.generatePublic(publicSpec);}
		catch (Exception e) {
			System.out.println(e);}
		System.out.println("Server public key found and imported.");
	}
	
	private void setServerStreams(){
		try {
			output = new ObjectOutputStream(server.getOutputStream());
			input = new ObjectInputStream(server.getInputStream());}
    	catch (Exception e){
    		System.out.println(e);}
		System.out.println("Server streams established.");
	}
	
	private void setLoginInfo(){
		try {
    		System.out.print("LOGIN NAME: ");
    		name = stdin.readLine();
    		System.out.print("PASSWORD: ");
    		password = stdin.readLine();
		} catch (Exception e) {
			System.out.println(e);}
	}
	
	private void sendCredentials(){
		try{
			Random rng = new SecureRandom();
			rng.nextBytes(nonce1); // 16 bytes = 128 bits
			System.out.println("Nonce chosen.");
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			pwHash = md.digest(password.getBytes()); // 64 bytes = 512 bits
			System.out.println("Password hashed.");
			sendData = makeLoginCreds(nonce1, pwHash, name);
	    	System.out.println("Send data prepared.");
	    	Cipher publicChiper = Cipher.getInstance("RSA");
			publicChiper.init(Cipher.ENCRYPT_MODE, serverKey);
			encryptedSendData = publicChiper.doFinal(sendData);
			System.out.println("Send data encrypted.");
			output.write(encryptedSendData);
			System.out.println("Credentials sent.");
		}
		catch (Exception e){
			System.out.println(e);}
	}
		
	private byte[] makeLoginCreds(byte[] nonce, byte[] hash, String name) throws IOException{
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		outputStream.write(nonce);
		outputStream.write(hash);
		outputStream.write(name.getBytes());
		return outputStream.toByteArray();
	}
	
	private void echoCookie(){
		try {
			input.readFully(cookie);
			output.write(cookie);
			System.out.println("Cookie received and returned.");
		}
		catch(Exception e){
			System.out.println(e);
		}
	}
	
	private void serverWelcome(){
		try{
			System.out.println((String)input.readObject());
		}
		catch (Exception e){
			System.out.println(e);
		}
	}
	
	private void processCommand(){
		try{
			while(true){
		
				System.out.println("Type 'list' for a list of available users.\n");
				System.out.println("Type 'send <USER> <MESSAGE>' to send that user a message.\n");
				System.out.println("Type 'logout' to logout.\n");
				String command = stdin.readLine();
				if(command.equalsIgnoreCase("list")){
					output.writeObject((String)"list");
					System.out.println((String)input.readObject());
				}
				else if(command.startsWith("send ")){
					doSend(command.substring(5));
				}
				else if(command.equalsIgnoreCase("logout")){
					System.out.println("Logging you out, come back soon!\n");
					output.writeObject((String)"logout");
					dcFromServer();
					return;
				}
				else{
					System.out.println("Bad input, try again.\n");
				}
			}
		}catch (Exception e){
			System.out.println(e);
		}
	}
	
	private void doSend(String nameAndMsg){
		int endNameIndex = nameAndMsg.indexOf(" ");
		String newRecipient = nameAndMsg.substring(0, endNameIndex);
		String message = nameAndMsg.substring(endNameIndex + 1);
		
		//if(haveCreds && haveDH)...
		
		try{
			output.writeObject((String)"connect " + recipient);
			String maybeFound = (String)input.readObject();
			if(maybeFound.equals("none")){
				System.out.println("No such user, try again.");
				return;
			}
			
			recipient = newRecipient;
			recipientINA = (InetAddress)input.readObject();
			
			byte[] forA = (byte[])input.readObject();
			byte[] nonce1Check = (byte[])input.readObject();
			ticketToB = (byte[])input.readObject();
			byte[] signature = (byte[])input.readObject();
			
			Signature sig = Signature.getInstance("SHA512withRSA");
			sig.initVerify(serverKey);
			sig.update(forA);
			sig.update(nonce1Check);
			sig.update(ticketToB);
			
			// Verify the signature of the above data
			if(!sig.verify(signature)){
				System.out.println("Signature verification failed.");
				return;
			}
			if(nonce1 != nonce1Check){
				System.out.println("The nonce was different.");
				return;
			}
			
			byte[] keyOfA = Arrays.copyOf(pwHash, 16); // use only first 128 bit
			SecretKeySpec secretKeySpecA = new SecretKeySpec(keyOfA, "AES");
			Cipher secCipher = Cipher.getInstance("AES");
			secCipher.init(Cipher.DECRYPT_MODE, secretKeySpecA);
			byte[] decryptedToCheck = secCipher.doFinal(forA);
			
			byte[] signatureKeyBytes = Arrays.copyOfRange(decryptedToCheck, 0, 128);
			byte[] verifyKeyBytes = Arrays.copyOfRange(decryptedToCheck, 128, 256);
			byte[] otherNameBytes = Arrays.copyOfRange(decryptedToCheck, 256, decryptedToCheck.length);
			String nameToCheck = new String(otherNameBytes);
			
			if(!nameToCheck.equals(newRecipient)){
				System.out.println("These are credentials for the wrong person!");
				return;
			}
			
			KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
			PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(signatureKeyBytes);
			X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(verifyKeyBytes);
			signatureKey = rsaKeyFactory.generatePrivate(privateSpec);
			verificationKey = rsaKeyFactory.generatePublic(publicSpec);
			
			connectToB();
			establishDHAsA();
			
		}
		catch(Exception e){
			System.out.println(e);
		}
	}
	
	private void connectToB(){
		try {
			recipientSocket = new Socket(recipientINA, serverPort + 1);
			outputB = new ObjectOutputStream(recipientSocket.getOutputStream());
			inputB = new ObjectInputStream(recipientSocket.getInputStream());
			System.out.println("Connect to " + recipient + ", streams set up.");
		} catch (Exception e) {
			System.out.println(e);
		}
	}
	
	private void establishDHAsA(){
		try {
			outputB.writeObject((byte[])ticketToB);
			byte[] cookieB = (byte[])inputB.readObject();
			
			
			// Use the values to generate a key pair
		    KeyPairGenerator dhKeyGen = KeyPairGenerator.getInstance("DH");
		    DHParameterSpec dhSpec = new DHParameterSpec(p, g, l);
		    dhKeyGen.initialize(dhSpec);
		    KeyPair dhKeyPair = dhKeyGen.generateKeyPair();

		    // Get the generated public and private keys
		    PrivateKey dhPrivateKeyA = dhKeyPair.getPrivate();
		    PublicKey dhPublicKeyA = dhKeyPair.getPublic();

		    // Send the public key bytes to the other party signed with our private key
		    byte[] dhPublicKeyBytesA = dhPublicKeyA.getEncoded();
		    
		    Signature signMyDH = Signature.getInstance("SHA512withRSA");
		    signMyDH.initSign(signatureKey);
		    signMyDH.update(name.getBytes());
		    signMyDH.update(dhPublicKeyBytesA);
			byte[] signature = signMyDH.sign();
		    
			output.writeObject((byte[])cookieB);
			output.writeObject((byte[])name.getBytes());
			output.writeObject((byte[])dhPublicKeyBytesA);
			output.writeObject((byte[])signature);
		    
			
		    // Retrieve the name, public key, and signature bytes of the other party
			byte[] checkNameBytes = (byte[])inputB.readObject();
			byte[] publicKeyBytesB = (byte[])inputB.readObject();
			byte[] signatureB = (byte[])inputB.readObject();
			String checkName = new String(checkNameBytes);
			
			Signature verifyHisDH = Signature.getInstance("SHA512withRSA");
			verifyHisDH.initVerify(verificationKey);
			verifyHisDH.update(checkNameBytes);
			verifyHisDH.update(publicKeyBytesB);
						
			// Verify the signature of the above data
			if(!verifyHisDH.verify(signatureB)){
				System.out.println("Signature verification failed.");
				return;
			}
			if(!checkName.equals(recipient)){
				System.out.println("This is a key for the wrong person!");
				return;
			}
			
			// Calculate Kab, the shared, perfect secret key
		    // Convert the public key bytes into a PublicKey object
		    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKeyBytesB);
		    KeyFactory keyFact = KeyFactory.getInstance("DH");
		    PublicKey dhPublicKeyB = keyFact.generatePublic(x509KeySpec);

		    // Prepare to generate the secret key with the private key and public key of the other party
		    KeyAgreement ka = KeyAgreement.getInstance("DH");
		    ka.init(dhPrivateKeyA);
		    ka.doPhase(dhPublicKeyB, true);

		    // Generate the secret key
		    perfectSecretKey = ka.generateSecret("DES");
		    
		    //Hash, send, check, then done
		    MessageDigest md = MessageDigest.getInstance("SHA-512");
			output.writeObject((byte[])md.digest(perfectSecretKey.getEncoded()));
			byte[] keyHashToCheck = ((byte[])input.readObject());
			int one = 1;
			byte[] oneBytes = Integer.
			
			byte[] keyBytesPlus1 = 
			
		} catch (Exception e) {
			System.out.println(e);
		}
	}
	
	private void establishDHAsB(){
		try {
			byte[] myTicket = (byte[])inputB.readObject();
			
			Random rng = new SecureRandom();
			byte[] nonce2 = new byte[16];
			rng.nextBytes(nonce2); // 16 bytes = 128 bits
			byte[] ipOfA = listening.getInetAddress().getAddress();
			ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
			outputStream.write(ipOfA);
			outputStream.write(nonce2);
			MessageDigest md = MessageDigest.getInstance("SHA-512");
			output.writeObject((byte[])md.digest(outputStream.toByteArray()));
			
			
			
			byte[] cookieB = (byte[])inputB.readObject();
			outputB.writeObject((byte[])ticketToB);
			
			
			// Use the values to generate a key pair
		    KeyPairGenerator dhKeyGen = KeyPairGenerator.getInstance("DH");
		    DHParameterSpec dhSpec = new DHParameterSpec(p, g, l);
		    dhKeyGen.initialize(dhSpec);
		    KeyPair dhKeyPair = dhKeyGen.generateKeyPair();

		    // Get the generated public and private keys
		    PrivateKey dhPrivateKeyA = dhKeyPair.getPrivate();
		    PublicKey dhPublicKeyA = dhKeyPair.getPublic();

		    // Send the public key bytes to the other party...
		    byte[] dhPublicKeyBytesA = dhPublicKeyA.getEncoded();
		    outputB.writeObject((byte[])dhPublicKeyBytesA);
		    
		    // Retrieve the public key bytes of the other party
		    byte[] publicKeyBytesB = (byte[])inputB.readObject();

		    // Convert the public key bytes into a PublicKey object
		    X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(publicKeyBytesB);
		    KeyFactory keyFact = KeyFactory.getInstance("DH");
		    PublicKey dhPublicKeyB = keyFact.generatePublic(x509KeySpec);

		    // Prepare to generate the secret key with the private key and public key of the other party
		    KeyAgreement ka = KeyAgreement.getInstance("DH");
		    ka.init(dhPrivateKeyA);
		    ka.doPhase(dhPublicKeyB, true);

		    // Generate the secret key
		    perfectSecretKey = ka.generateSecret("DES");
		
		} catch (Exception e) {
			System.out.println(e);
		}
	}
	
	private void dcFromServer(){
		try{
			input.close();
			output.close();
			server.close();}
		catch(Exception e){
			System.out.println(e);
		}
	}
	
	private void forgetRecipient(){
		recipient = null;
		signatureKey = null;
		verificationKey = null;
	}
	
	private void dcFromB(){
		try{
			inputB.close();
			outputB.close();
			recipientSocket.close();
			
		}
		catch(Exception e){
			System.out.println(e);
		}
	}
	// read bytes from a file
	public static byte[] readByteFromFile(File f) throws Exception {
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
		

	
	
	

}
