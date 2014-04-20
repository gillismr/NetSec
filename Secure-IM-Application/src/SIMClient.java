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

public class SIMClient {

	public static void main(String[] args) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchPaddingException {
    	
    	Socket server = null;
    	Socket recipient = null;
    	ServerSocket listening = null;
    	
    	BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
    	Scanner sc = null;
    	
    	byte[] serverKeyBytes = null;
    	byte[] sendData;
    	byte[] receiveData = new byte[1024];
    	
    	DataInputStream input = null;
        DataOutputStream output = null;
        //DataInputStream inputLine = null;
    	
        String message; 
    	String name = "";
    	String password = "";
    	//byte[] pwHash;
    	
    	try {
			sc = new Scanner(new File("config.txt"));
			serverKeyBytes = readByteFromFile(new File("pub1.class"));
		} catch (Exception e) {
			System.out.println("Config file and/or server public key not found, please ensure the properly titled config.txt and pub1.class files are in the working directory");
			e.printStackTrace();
		}
    	
    	KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
		X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(serverKeyBytes);
		PublicKey serverKey = rsaKeyFactory.generatePublic(publicSpec);
    	System.out.println("Server info and public key found. Configuring connection to server...");
    	
    	try {
			server = new Socket(sc.next(), Integer.parseInt(sc.next()));
		} catch (NoSuchElementException e){
			System.out.println("Incorrect formatting of config file, please ensure it contains the server IP addess on the first line and port number on the second");
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
    	
    	output = new DataOutputStream(server.getOutputStream());
    	input = new DataInputStream(server.getInputStream());
    	System.out.println("Server connection and I/O streams established. Login required.");
    	
    	System.out.print("LOGIN NAME: ");
    	try {
			name = stdin.readLine();
		} catch (IOException e) {
			System.out.println("There was an IOException. Please learn how to computer.");
			e.printStackTrace();
		}
    	System.out.print("PASSWORD: ");
    	try {
			password = stdin.readLine();
		} catch (IOException e) {
			System.out.println("There was an IOException. Please learn how to computer.");
			e.printStackTrace();
		}
    	
    	Random rng = new SecureRandom();
    	byte[] nonce1 = new byte[16]; // 16 bytes = 128 bits
    	rng.nextBytes(nonce1);
    	System.out.println("Nonce chosen.");
    	
    	MessageDigest md = MessageDigest.getInstance("SHA-512");
    	byte[] pwHash = md.digest(password.getBytes()); //64bytes = 512 bits
    	System.out.println("Password hashed.");
    	
    	sendData = makeLoginCreds(nonce1, pwHash, name);
    	System.out.println("Send data prepared.");
    	
    	Cipher publicChiper = Cipher.getInstance("RSA");
		publicChiper.init(Cipher.ENCRYPT_MODE, serverKey);
		byte[] encryptedSendData = publicChiper.doFinal(sendData);
		System.out.println("Send data encrypted.");
		
		output.write(encryptedSendData);
    	System.out.println("Data sent. Dealing with cookies...");
    	
    	byte[] cookie = new byte[64]; // 64bytes = 512 bits
    	input.readFully(cookie);
    	output.write(cookie);
    	
    	//At this point, the server should start handling what we want to do exactly...
    	
    	
    	
    	
    	
    }
	
	private static byte[] makeLoginCreds(byte[] nonce, byte[] hash, String name) throws IOException{
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		outputStream.write(nonce);
		outputStream.write(hash);
		outputStream.write(name.getBytes());
		return outputStream.toByteArray();
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
