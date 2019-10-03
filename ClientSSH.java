import java.net.*;
import java.io.*;
import java.security.*;
import java.text.*;
import java.util.*;
import java.sql.*;


import java.math.BigInteger;
import java.lang.Math;

import paillierp.*;
import paillierp.key.*;
import paillierp.zkp.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class ClientSSH {

    //In practice, the following method was less useful than anticipated and we still needed some manual sockets.
    public static Object serverSwapObjects(int port, Object returnMessage) throws IOException, ClassNotFoundException {
        ServerSocket serverSocket = new ServerSocket(port);
        Socket socket = serverSocket.accept();
        OutputStream outputStream = socket.getOutputStream();
        InputStream inputStream = socket.getInputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
        ObjectInputStream objectInputStream = new ObjectInputStream((inputStream));
        objectOutputStream.writeObject(returnMessage);
        Object payload = objectInputStream.readObject();
        serverSocket.close();
        socket.close();
        return payload;
    }

    //This is used to create the "noise" factor for differential privacy
    public static double laplace(double scale) {
        double exponential_sample1 = -scale * Math.log(Math.random());
        double exponential_sample2 = -scale * Math.log(Math.random());
        return exponential_sample1 - exponential_sample2;
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, SQLException, ClassNotFoundException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        int port = 8080;

        //first we create a public key so the Paillier key doesn't have to be sent through clear channels
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048,new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();
        Cipher decryptionCipher = Cipher.getInstance("RSA");
        decryptionCipher.init(Cipher.DECRYPT_MODE,privateKey);
        System.out.println("Client " + InetAddress.getLocalHost() + " RSA key pair generated!");

        Object junk;
        junk = serverSwapObjects(port,publicKey);  //we only want to send our public key; the Aggregator has nothing we need now
        System.out.println("Client " + InetAddress.getLocalHost() + "Aggregator address received and public key sent");

        byte[] encryptedPaillierKey = (byte[]) serverSwapObjects(port,"confirmed");
        byte[] decryptedPaillierKey = decryptionCipher.doFinal(encryptedPaillierKey);

        PaillierPrivateThresholdKey myKey = new PaillierPrivateThresholdKey(decryptedPaillierKey,1L);
        //the seed is unimportant at this stage, but the constructor wants it.
        PaillierThreshold decryptionKey = new PaillierThreshold(myKey);
        Paillier encryptionKey = new Paillier(decryptionKey.getPublicKey());
        System.out.println("Client " + InetAddress.getLocalHost() + " Paillier key received!");


        //For the rest of the run we should only be receiving Strings, the first character of which describes the message type
        //We have q-query, e-encrypted, and k-kill
        String serverMessageAndType;
        ServerSocket serverSocket = new ServerSocket(port);
        while(true){
            Socket socket = serverSocket.accept();
            OutputStream outputStream = socket.getOutputStream();
            InputStream inputStream = socket.getInputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
            ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
            serverMessageAndType = (String) objectInputStream.readObject();
            char messageType = serverMessageAndType.charAt(0);
            String serverMessage = serverMessageAndType.substring(1);
            System.out.println("Client " + InetAddress.getLocalHost() + " received message of type " + messageType);
            switch (messageType) {
                case 'q': {//query
                    //create the database connection -- we'll use same basic configuration for each database here
                    //fancy future version will have something like a JSON table that has db info, aliases, etc
                    // create our mysql database connection
                    String[] queryAndNoise = serverMessage.split("&&&");
                    //We will have query &&& result1:epsilon1 &&& result2:epsilon2...
                    //Note that result is always an integer, because that's all we can encode with this system
                    String query = queryAndNoise[0];
                    Connection conn = null;
                    Class.forName("com.mysql.jdbc.Driver");
                    String url = "jdbc:mysql://localhost:3306/testdb?";
                    String user = "testuser";
                    String password = "password";

                    conn = DriverManager.getConnection(url, user, password);

                    //perform the query.  Ideally the query can be stated precisely in terms of SQL statements.
                    //If we need to do further processing, this would be where we implement that
                    Statement statement = conn.createStatement();
                    ResultSet results = statement.executeQuery(query);
                    results.next();

                    //Add noise according to sensitivity; it is the Aggregator's job to allocate this
                    BigInteger[] encrypted_response = new BigInteger[queryAndNoise.length - 1];
                    for (int i = 1; i < queryAndNoise.length; i++) {
                        String[] dict = queryAndNoise[i].split(":");
                        double noise = laplace(Double.parseDouble(dict[1]));
                        int aggregate = results.getInt(dict[0]);
                        double aggPlusNoise = (aggregate + noise) * 100;
                        if(aggPlusNoise<1){
                            aggPlusNoise = 1; //This is a kludge, but some of our values are very small, and returning negatives
                            //could seriously mess everything up.
                        }
                        BigInteger aggregatePlusNoise = BigInteger.valueOf(Math.round(aggPlusNoise));
                        BigInteger encrypted_message = encryptionKey.encrypt(aggregatePlusNoise);
                        encrypted_response[i - 1] = encrypted_message;
                        //We're sending back 100 times the values we're looking for (in order to allow for decimals).
                        // For purposes of odds ratios this won't be problematic but it can show up elsewhere.
                    }
                    objectOutputStream.writeObject(encrypted_response);
                    objectOutputStream.writeObject("finished");
                    break;
                }


                case 'e': {//encrypted text
                //perform a partial decryption and return
                    objectOutputStream.writeObject(decryptionKey.decrypt((new BigInteger(serverMessage))));
                    break;
                }
                case 'k': {//kill the process...gracefully
                    socket.close();
                    serverSocket.close();
                    return;
                }
            }
            objectInputStream.close();
            objectOutputStream.close();
            socket.close();
        }
    }
}

