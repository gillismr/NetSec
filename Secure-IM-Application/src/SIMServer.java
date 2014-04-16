import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.List;

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
	
	//Initialize list of connected clients
	List<SocketAddress> clients = new ArrayList<SocketAddress>();

	//Initialize table of user names and PW hashes
	//What data type? 
	
	//Initialize data buffers?
	static byte[] sendData, receiveData;
	
	
	
	public static void main(String[] args) throws IOException {
		
		//Initialize Socket and Packet?
		@SuppressWarnings("resource")
		DatagramSocket serverSocket = new DatagramSocket(Integer.parseInt(args[0]));
		DatagramPacket packet = new DatagramPacket(receiveData, receiveData.length);
		System.out.println("Server Initialized, listening on port " + serverSocket.getPort() + "...");
		
		
		while(true){
	    	//Wait to receive a message
    		serverSocket.receive(packet);
    		
    		//If user is new, add them, set them up with their name and hash of their PW
    		
    		//If user is known, check that they provided the correct PW
    		//Get the hash matching the provided login name
    		//If it matches the provided hash, log the user in
    		
    		
		}
		
	}
	
	private String getList(){
		
	}

}
