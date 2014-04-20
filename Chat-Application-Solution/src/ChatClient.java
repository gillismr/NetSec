/* 	Jave Demo
	Network Security (CS6740/CS4740)
	Amirali Sanatinia (amirali@ccs.neu.edu)
*/

import java.net.*;

public class ChatClient {

	static final int MAX_UDP = 65507;
	static DatagramSocket socket = null;

	public static void main(String[] args) throws InterruptedException {
		while(true){
			Thread sndr = new Thread(new Sender());
			sndr.start();
			Thread.sleep(500);
		}
	}

	// Sending packets as a separate thread
	static class Sender implements Runnable {

		public void run() {

			String srvIP = "127.0.0.1";
			int srvPort = 6666;
			InetAddress srvAddr = null;

			// setup upd scoket
			try {
				socket = new DatagramSocket();
				srvAddr = InetAddress.getByName(srvIP);
			} catch (Exception e) {
				e.printStackTrace();
			}

			// sending packets
			byte[] data = new byte[MAX_UDP];
			data = "Hello World!".getBytes();
			DatagramPacket sndPacket = new DatagramPacket(data, data.length,
					srvAddr, srvPort);
			try {
				socket.send(sndPacket);
			} catch (Exception e) {
				e.printStackTrace();
			}
		}

	}

}