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

public class ClientSSH {

    public static double laplace(double scale) {
        double exponential_sample1 = -scale * Math.log(Math.random());
        double exponential_sample2 = -scale * Math.log(Math.random());
        return exponential_sample1 - exponential_sample2;
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, SQLException, ClassNotFoundException {
        //first we talk to the KeyMaster, sending it our public key and getting a paillier key
        int port = 8080;
        ServerSocket serverSocket = new ServerSocket(port);
        Socket publicKeySocket = serverSocket.accept();
        OutputStream publicKeyOutputStream = publicKeySocket.getOutputStream();
        ObjectOutputStream publicKeyObjectOutputStream = new ObjectOutputStream(publicKeyOutputStream);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024,new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        PublicKey publicKey = pair.getPublic();
        publicKeyObjectOutputStream.writeObject(publicKey);
        publicKeySocket.close();


       // try (ServerSocket serverSocket = new ServerSocket(port)) {

            //           while(true){
        Socket paillierKeySocket = serverSocket.accept();

        OutputStream paillierKeyOutputStream = paillierKeySocket.getOutputStream();
        InputStream paillierKeyInputStream = paillierKeySocket.getInputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(paillierKeyOutputStream);
        ObjectInputStream objectInputStream = new ObjectInputStream(paillierKeyInputStream);

//        PaillierThresholdKey privateKey;
        PaillierThreshold decryptionKey;
        PaillierPrivateThresholdKey myKey;
        byte[] bytestream;


        bytestream = (byte[]) objectInputStream.readObject();
        myKey = new PaillierPrivateThresholdKey(bytestream,1L);
        //the seed is unimportant at this stage, but the constructor wants it.  Sure.

        decryptionKey = new PaillierThreshold(myKey);
        objectOutputStream.writeObject("confirmed");


        Paillier encryptionKey = new Paillier(decryptionKey.getPublicKey());
        paillierKeySocket.close();

        // Now we are talking to the aggregator, which can have longer conversations.
        while (true) {
            Socket aggregatorSocket = serverSocket.accept();

            OutputStream outputStream1 = aggregatorSocket.getOutputStream();
            InputStream inputStream1 = aggregatorSocket.getInputStream();
            ObjectOutputStream objectOutputStream1 = new ObjectOutputStream(outputStream1);
            ObjectInputStream objectInputStream1 = new ObjectInputStream(inputStream1);
            String serverMessageAndType = (String) objectInputStream1.readObject();
            //String serverMessageAndType = "";
            while(objectInputStream1.available()>0){
                serverMessageAndType += (String) objectInputStream1.readObject();
            }
            System.out.println(serverMessageAndType);

            char messageType = serverMessageAndType.charAt(0);
            String serverMessage = serverMessageAndType.substring(1);
//                System.out.println(serverMessageAndType);
            System.out.println(messageType);
//                System.out.println(serverMessage);
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
                        //DriverManager.registerDriver(new com.mysql.jdbc.Driver());
                    String url = "jdbc:mysql://localhost:3306/testdb?";
                    String user = "testuser";
                    String password = "password";
                    Properties properties = new Properties();
                    properties.setProperty("user", "root");
                    properties.setProperty("password", "");

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
                        System.out.println(dict[0]);
                        int aggregate = results.getInt(dict[0]);
                        BigInteger aggregatePlusNoise = BigInteger.valueOf(Math.round(aggregate + noise) * 100);
                        BigInteger encrypted_message = encryptionKey.encrypt(aggregatePlusNoise);
                        encrypted_response[i - 1] = encrypted_message;
                        System.out.println(encrypted_message.toString(10));
                            //]Remember we're sending back 100 times the values we're looking for.
                            // For purposes of odds ratios this won't be problematic but it can show up elsewhere.
                    }
                    objectOutputStream1.writeObject(encrypted_response);
                    break;
                }





                case 'e': {//encrypted text
                        //perform a partial decryption and return
                        //System.out.println(serverMessage);
                    objectOutputStream1.writeObject(decryptionKey.decrypt(new BigInteger(serverMessage)));
                    break;
                }
                case 'k': {
                    aggregatorSocket.close();
                    serverSocket.close();
                    return;
                }
            }
            objectOutputStream1.close();
            objectInputStream1.close();
            aggregatorSocket.close();
//                serverSocket.close();
        }
    }
}

