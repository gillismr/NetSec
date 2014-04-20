import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.NoSuchElementException;
import java.util.Random;
import java.util.Scanner;

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

	public static void main(String[] args) throws NoSuchAlgorithmException {
    	
    	Socket server;
    	Socket recipient;
    	BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
    	byte[] sendData;
    	byte[] receiveData = new byte[1024];
    	DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
    	String message; 
    	String name;
    	String password = "";
    	Scanner sc = null;
    	//byte[] pwHash;
    	
    	try {
			sc = new Scanner(new File("config.txt"));
		} catch (FileNotFoundException e) {
			System.out.println("Config file not found, please ensure a properly titled config.txt file is in the working directory");
			e.printStackTrace();
		}
    	
    	System.out.println("Configuring connection to server...");
    	
    	try {
			server = new Socket(sc.next(), Integer.parseInt(sc.next()));
		} catch (NoSuchElementException e){
			System.out.println("Incorrect formatting of config file, please ensure it contains the server IP addess on the first line and port number on the second");
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
    	
    	System.out.println("Connected to server. Login required.");
    	
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
    	byte [] pwHash = md.digest(password.getBytes());
    	System.out.println("Password hashed.");
    	
    	sendData = 
    	
    	
    	System.out.println("Credentials received, password hashed, nonce chosen. Initiating communication with server...");
    	
    	
    	
    	
    }
		
		
		
	
	
	

}
