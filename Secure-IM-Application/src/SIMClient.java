import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.NoSuchElementException;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/*
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.io.*;
*/

public class SIMClient{

	//Fields for server connection configuration
	Scanner sc;
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
    
	private Socket recipientSocket;
	private ServerSocket listening;
	
	
	
	
	public SIMClient(){
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
    	
		SIMClient thisClient = new SIMClient();
		
    }
	
	private void connectToServer(){
		try {
			sc = new Scanner(new File("config.txt"));
			server = new Socket(sc.next(), Integer.parseInt(sc.next()));}
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
		String recipient = nameAndMsg.substring(0, endNameIndex);
		String message = nameAndMsg.substring(endNameIndex + 1);
		
		//if(haveCreds && haveDH)...
		
		try{
			output.writeObject((String)"connect " + recipient);
			
		}
		catch(Exception e){
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
