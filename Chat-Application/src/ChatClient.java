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


import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;

public class ChatClient
{
    public static void main(String args[])throws IOException
    {
    	BufferedReader stdin = new BufferedReader(new InputStreamReader(System.in));
        
    	//Initialize things
    	byte[] sendData = new byte[1024];
        byte[] receiveData = new byte[1024];
        DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
        String message;
        
        //Use the runtime parameters to create a socket connected to the proper server and port
        InetSocketAddress server = new InetSocketAddress(args[0], Integer.parseInt(args[1]));
        
        @SuppressWarnings("resource")
		DatagramSocket clientSocket = new DatagramSocket();
        System.out.println("Welcome to ChatClient, successfully connected to server (I think...)");
        while(true){
	        	
	        System.out.println("Please enter your message:");
	        message = stdin.readLine();
	        
	        //Send the previously input message to the server
	        sendData = message.getBytes();  
	        DatagramPacket sendPacket = new DatagramPacket(sendData, sendData.length, server);
	        clientSocket.send(sendPacket);
	        
	        //Receive messages from the server and print them
	        clientSocket.receive(receivePacket);
	        message = new String(receivePacket.getData(), "UTF-8");
	        System.out.println(message);
        }
    }
}