//I did not have time to figure out threading. I found some resources and realize that I could use ExecutorService
//by passing it a runnable Listener/Handler which in turn is passed the DatagramSockets I use below. As I have
//mentioned before, I have been playing catch-up in this class from day 1, and this is the best I could do.
//I did enjoy getting this far, and if possible I WOULD LOVE THE CHANCE TO GET THIS WORKING CORRECTLY for some 
//additional, partial credit. If an extension is possible, please let me know.

//This program works but has many bugs, such as...
//   	-if you send/receive a long message and then a short one, the short one is simply overwritten onto the long
//			message and the whole thing gets sent
//		-if client 1 sends messages, then client 2 sends messages, there's a chance that client 1 will have to send 
//			more messages before he begins to see the backlog of client 2's messages

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.util.ArrayList;
import java.util.List;

public class ChatServer
{
    public static void main(String args[])throws IOException
    {
        //Initialize data buffers
    	byte[] sendData = new byte[1024];
    	byte[] receiveData = new byte[1024];
    	
    	//Initialize list of connected clients
    	List<SocketAddress> clients = new ArrayList<SocketAddress>();
    	
    	//Initialize Socket and Packet
    	@SuppressWarnings("resource")
		DatagramSocket serverSocket = new DatagramSocket(Integer.parseInt(args[0]));
		DatagramPacket packet = new DatagramPacket(receiveData, receiveData.length);
    	System.out.println("Server Initialized, listening on port " + serverSocket.getPort() + "...");
    	
    	while(true){
	    	//Wait to receive a message
    		serverSocket.receive(packet);
	    	
    		//If the message comes from a new client, add their IP to the list
    		if (!clients.contains(packet.getSocketAddress()))
	    	    clients.add(packet.getSocketAddress());
	    	
    		//Create the string that will be sent to all clients
    		String broadcast = new String("<From " + packet.getSocketAddress().toString() + ">: " + new String(packet.getData(), "UTF-8"));
	    	System.out.println("Received message " + broadcast); 
	    	
	    	//Convert the aforementioned string to a byte[] and send it to all clients
	    	sendData = broadcast.getBytes();
	    	for (SocketAddress a : clients)
	    	    serverSocket.send(new DatagramPacket(sendData, sendData.length, a));
	    	
	    }
    		    
    }
}   
