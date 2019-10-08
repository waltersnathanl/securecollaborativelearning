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

        ServerSocket serverSocket = new ServerSocket(port);
        Socket socket;
        OutputStream outputStream;
        InputStream inputStream;
        ObjectOutputStream objectOutputStream;
        ObjectInputStream objectInputStream;

        //Step one: transmit public Key when prompted
        socket = serverSocket.accept();
        outputStream = socket.getOutputStream();
        objectOutputStream = new ObjectOutputStream(outputStream);
        objectOutputStream.writeObject(publicKey);
        System.out.println("Client " + InetAddress.getLocalHost() + ": Public key sent");
        objectOutputStream.close();
        socket.close();

        /*
        TODO - Switch things around to fit AggregatorSSH.  We're going to open a proper socket.
        We will receive a Paillier key and a Long salt value.  Then we will add the salt to AggPlusNoise
         */

        socket = serverSocket.accept();
        inputStream = socket.getInputStream();
        objectInputStream = new ObjectInputStream(inputStream);
        byte[] encryptedPaillierKey = (byte[]) objectInputStream.readObject();
        int salt = (int) objectInputStream.readObject();
        objectInputStream.close();
        socket.close();
        System.out.println("Client " + InetAddress.getLocalHost() + ": received Paillier key and salt value");

        byte[] decryptedPaillierKey = decryptionCipher.doFinal(encryptedPaillierKey);
        PaillierPrivateThresholdKey myKey = new PaillierPrivateThresholdKey(decryptedPaillierKey,1L);
        //the seed is unimportant at this stage, but the constructor requires a value.
        PaillierThreshold decryptionKey = new PaillierThreshold(myKey);
        Paillier encryptionKey = new Paillier(decryptionKey.getPublicKey());
        System.out.println("Client " + InetAddress.getLocalHost() + " Paillier key received!");


        //For the rest of the run we should only be receiving Strings, the first character of which describes the message type
        //We have q-query, e-encrypted number, and k-kill the process

        String serverMessageAndType;
        while(true){
            socket = serverSocket.accept();
            outputStream = socket.getOutputStream();
            inputStream = socket.getInputStream();
            objectOutputStream = new ObjectOutputStream(outputStream);
            objectInputStream = new ObjectInputStream(inputStream);
            serverMessageAndType = (String) objectInputStream.readObject();
            char messageType = serverMessageAndType.charAt(0);
            String serverMessage = serverMessageAndType.substring(1);
            switch (messageType) {
                case 'q': {//query
                    System.out.println("Client " + InetAddress.getLocalHost() + " received a SQL query");
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

                    //perform the query.
                    Statement statement = conn.createStatement();
                    ResultSet results = statement.executeQuery(query);
                    results.next();

                    //Add noise according to sensitivity; it is the Aggregator's job to allocate this
                    BigInteger[] encrypted_response = new BigInteger[queryAndNoise.length - 1];
                    for (int i = 1; i < queryAndNoise.length; i++) {
                        String[] dict = queryAndNoise[i].split(":");
                        double noise = laplace(Double.parseDouble(dict[1]));
                        int aggregate = results.getInt(dict[0]);
                        Long responseValue = Math.round((aggregate + noise) * 100) + salt;
                        if(responseValue<1){
                            responseValue = 1L; //This is probably no longer necessary with the positive integer salt value
                            //but there's no reason to remove it as encrypting a negative throws an exception
                        }
                        BigInteger aggregatePlusNoise = BigInteger.valueOf(responseValue);

                        BigInteger encrypted_message = encryptionKey.encrypt(aggregatePlusNoise);
                        encrypted_response[i - 1] = encrypted_message;
                        //We're sending back 100 times the values we're looking for (in order to allow for decimals).
                        // For purposes of odds ratios this won't be problematic but it can show up elsewhere.
                    }
                    objectOutputStream.writeObject(encrypted_response);
                    //objectOutputStream.writeObject("finished");
                    break;
                }


                case 'e': {//encrypted text
                //perform a partial decryption and return
                    System.out.println("Client " + InetAddress.getLocalHost() + " received an encrypted number");
                    objectOutputStream.writeObject(decryptionKey.decrypt((new BigInteger(serverMessage))));
                    break;
                }
                case 'k': {//kill the process...gracefully
                    System.out.println("Client " + InetAddress.getLocalHost() + " received stand down order");
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

