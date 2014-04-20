import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.PrintStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import javax.crypto.Cipher;


/*
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.List;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;
import java.io.*;
*/


public class SIMServer {
	
	public static void main(String[] args) throws IOException, GeneralSecurityException {
		
		@SuppressWarnings("resource")
		ServerSocket serverSocket = new ServerSocket(9090);
		byte[] privateKeyBytes = readByteFromFile(new File("priv1.class"));
		
		KeyFactory rsaKeyFactory = KeyFactory.getInstance("RSA");
		PKCS8EncodedKeySpec privateSpec = new PKCS8EncodedKeySpec(privateKeyBytes);
		PrivateKey privateKey = rsaKeyFactory.generatePrivate(privateSpec);
		
		Random rng = new SecureRandom();
    	byte[] cookieNonce = new byte[16]; // 16 bytes = 128 bits
    	rng.nextBytes(cookieNonce);
    	
		while(true){
	    	Socket clientSocket = serverSocket.accept();
	    	ClientThread c = new ClientThread(clientSocket, privateKey, cookieNonce);
	    	c.start();
		}
		
	}
	
	// read bytes from a file
	public static byte[] readByteFromFile(File f) throws IOException{
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

class ClientEntry{
	
	public String name;
	public byte[] pwHash;
	public InetAddress ip;
	public boolean available;
	
		
	public ClientEntry(String name, byte[] pwHash, InetAddress ip, boolean available){
		this.name = name;
		this.pwHash = pwHash;
		this.ip = ip;
		this.available = available;
	}
	
	public void setIP(InetAddress newIP){
		this.ip = newIP;
	}
		
	public void setAvailable(boolean available){
		this.available = available;
	}
}



class ClientThread extends Thread {
	
	private ObjectInputStream input = null;
	private ObjectOutputStream output = null;
	private Socket clientSocket = null;
	private PrivateKey privateKey;
	private byte[] cookieNonce;
	private byte[] nonce1, pwHash, nameBytes;
	private int clientIndex;
	private ClientEntry clientEntry;
	private InetAddress ip;
	String name;
	
	private static final List<ClientEntry> clients = new ArrayList<ClientEntry>();

	public ClientThread(Socket clientSocket, PrivateKey privateKey, byte[] cookieNonce) throws IOException, NoSuchAlgorithmException {
		this.clientSocket = clientSocket;
		this.input = new ObjectInputStream(clientSocket.getInputStream());
		this.output = new ObjectOutputStream(clientSocket.getOutputStream());
		this.privateKey = privateKey;
		this.cookieNonce = cookieNonce;
	}

	public void run() {
		byte[] initialCreds;
		try {
			initialCreds = (byte[])input.readObject();
			System.out.println("Initial credentials received, sending cookie.");
			output.writeObject((byte[])makeCookie());
			System.out.println("Cookie sent, awaiting response.");
			if(!checkCookie((byte[])input.readObject())){
				disconnect();
				return;
			}
			
			System.out.println("Cookie received, IP address verified. Decrypting initial credentials.");
			Cipher privateCipher = Cipher.getInstance("RSA");
			privateCipher.init(Cipher.DECRYPT_MODE, privateKey);
			byte[] decryptedCreds = privateCipher.doFinal(initialCreds);
			
			System.out.println("Credentials decrypted. Seperating peices.");
			nonce1 = Arrays.copyOfRange(decryptedCreds, 0, 16);
			pwHash = Arrays.copyOfRange(decryptedCreds, 16, 80);
			nameBytes = Arrays.copyOfRange(decryptedCreds, 80, decryptedCreds.length);
			name = new String(nameBytes);
			
			System.out.println("Credentials separated for user " + name + ". Checking login history...");
			clientIndex = getClientIndex(name);
			
			if(clientIndex == -1){
				System.out.println("New user detected, creating new client entry. Better hope they used the correct password...");
				clientEntry = new ClientEntry(name, pwHash, clientSocket.getInetAddress(), true);
				clients.add(clientEntry);
				clientIndex = clients.indexOf(clientEntry);
			}
			else if (correctPassword()){
				System.out.println("Password verified. Updating IP address and availability for this session.");
				clients.get(clientIndex).setIP(clientSocket.getInetAddress());
				clients.get(clientIndex).setAvailable(true);
			}
			else{
				System.out.println("Incorrect PW, terminating session.");
				output.writeObject((String)"Incorrect PW, terminating session.");
				disconnect();
				return;
			}
			
			output.writeObject((String)"Welcome, " + name + ".\n");
			
			while(true){
				output.writeObject((String)"Type 'list' for a list of available users.\n");
				output.writeObject((String)"Type 'send <USER> <MESSAGE>' to send that user a message.\n");
				output.writeObject((String)"Type 'logout' to logout.\n");
				String command = (String)input.readObject();
				if(command.equalsIgnoreCase("list")){
					listClients();
				}
				else if(command.startsWith("send ")){
					
				}
				else if(command.equalsIgnoreCase("logout")){
					output.writeObject((String)"Logging you out, come back soon!\n");
					clients.get(clientIndex).setAvailable(false);
					disconnect();
					return;
				}
				else{
					output.writeObject((String)"Bad input, try again.\n");
				}
				
			}
			
		} 
		catch (Exception e) {
		}
	}
	
	private void disconnect() throws IOException{
		input.close();
		output.close();
		clientSocket.close();
	}
	
	private byte[] makeCookie() throws Exception{
		byte[] ip = this.clientSocket.getInetAddress().getAddress();
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream( );
		outputStream.write(ip);
		outputStream.write(this.cookieNonce);
		MessageDigest md = MessageDigest.getInstance("SHA-512");
		return md.digest(outputStream.toByteArray());
	}
	
	private boolean checkCookie(byte[] providedCookie) throws Exception{
		byte[] freshCookie = makeCookie();
		return (providedCookie == freshCookie);
	}
	
	
	//Returns the index of the clients login/session info if they are known. Returns -1 if they are unknown
	private int getClientIndex(String name){
		for(ClientEntry ce:clients){
			if(ce.name.equals(name)){
				return clients.indexOf(ce);
			}
		}
		return -1;
	}
	
	private boolean correctPassword(){
		return (pwHash == clients.get(clientIndex).pwHash);
	}
	
	private void listClients() throws IOException{
		for(ClientEntry ce:clients){
			if(!ce.name.equals(name) && ce.available){
				output.writeObject((String)ce.name + "\n");
			}
		}
	}
	
	
		
	
	
	
	
	
	
}
	



