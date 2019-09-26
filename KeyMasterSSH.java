import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Random;

import paillierp.*;
import paillierp.key.*;
import paillierp.zkp.*;

public class KeyMasterSSH {
    public static void main(String[] args) throws IOException {
        //if (args.length < 1) return;
        //int port = Integer.parseInt(args[0]);
        int port = 8080;
        try (ServerSocket serverSocket = new ServerSocket(port)) {

            //           while(true){
            Socket socket = serverSocket.accept();

            OutputStream outputStream = socket.getOutputStream();
            InputStream inputStream = socket.getInputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
            ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);

            String[] addresses = (String[]) objectInputStream.readObject();
            int number_of_keys = addresses.length;
            //For now, we will make it so all clients can work together to decrypt the aggregates.  Ideally we would
            //make the aggregator unable to participate, but at the moment it seems difficult to make a true public key
            //using the Paillier package, and it's not worth the time it would take to fix it.

            Random rnd = new Random();
            PaillierPrivateThresholdKey[] keys = KeyGen.PaillierThresholdKey(128, number_of_keys, number_of_keys - 1, rnd.nextLong());

            byte[] currentMessage;

            for (int i = 0; i < number_of_keys; i++) {
                try (Socket socket1 = new Socket(addresses[i], 8080)) {
                    OutputStream outputStream1 = socket1.getOutputStream();
                    InputStream inputStream1 = socket1.getInputStream();
                    ObjectOutputStream objectOutputStream1 = new ObjectOutputStream(outputStream1);
                    ObjectInputStream objectInputStream1 = new ObjectInputStream(inputStream1);
                    currentMessage = keys[i].toByteArray();
                    objectOutputStream1.writeObject(currentMessage);
                    while (objectInputStream1.available() > 0) {
                        System.out.println((String) objectInputStream1.readObject());
                    }



                } catch (ClassNotFoundException e) {
                    e.printStackTrace();

                }
            }
            System.out.println("Keys Delivered.  Signing off.");
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        }
    }
}
