import java.net.*;
import java.io.*;
import java.text.*;
import java.util.*;
import java.sql.*;


import java.math.BigInteger;
import java.lang.Math;

import paillierp.*;
import paillierp.key.PaillierPrivateThresholdKey;
import paillierp.key.PaillierThresholdKey;

public class ClientServer {

    public class Message implements Serializable{
        //My goal here is to create a single uniform message object that can contain a key, a SQL query, a dictionary of epsilon values, or an encrypted message.
    }

    public static double laplace(double scale) {
        double exponential_sample1 = -scale * Math.log(Math.random());
        double exponential_sample2 = -scale * Math.log(Math.random());
        return exponential_sample1 - exponential_sample2;
    }

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

            PaillierThresholdKey privateKey;
            PaillierThreshold decryptionKey;
            PaillierPrivateThresholdKey myKey;
            byte[] bytestream;


            bytestream = (byte[]) objectInputStream.readObject();
            myKey = new PaillierPrivateThresholdKey(bytestream,30L);

            decryptionKey = new PaillierThreshold(privateKey);
            objectOutputStream.writeObject("confirmed");


            Paillier encryptionKey = new Paillier(decryptionKey.getPublicKey());



            socket.close();
            while (true) {
                Socket socket1 = serverSocket.accept();

                OutputStream outputStream1 = socket.getOutputStream();
                InputStream inputStream1 = socket.getInputStream();
                ObjectOutputStream objectOutputStream1 = new ObjectOutputStream(outputStream);
                ObjectInputStream objectInputStream1 = new ObjectInputStream(inputStream);
                String serverMessageAndType = "k";
                while(objectInputStream1.available()>0){
                    serverMessageAndType = (String) objectInputStream1.readObject();
                }

                char messageType = serverMessageAndType.charAt(0);
                String serverMessage = serverMessageAndType.substring(1);
                switch (messageType) {
                    case 'q': //query

                            //create the database connection -- we'll use same basic configuration for each database here
                            //fancy future version will have something like a JSON table that has db info, aliases, etc
                            // create our mysql database connection
                            String[] queryAndNoise = serverMessage.split("&&&");
                            //We will have query &&& result1:epsilon1 &&& result2:epsilon2...
                            //Note that result is always an integer, because that's all we can encode with this system
                            String query = queryAndNoise[0];
                            String myDriver = "com.mysql.jdbc.Driver";
                            String myUrl = "jdbc:mysql://localhost/testdb";
                            Class.forName(myDriver);
                            Connection conn = DriverManager.getConnection(myUrl, "testuser", "password");

                            //perform the query.  Ideally the query can be stated precisely in terms of SQL statements.
                            //If we need to do further processing, this would be where we implement that
                            Statement statement = conn.createStatement();
                            ResultSet results = statement.executeQuery(query);

                            //Add noise according to sensitivity; it is the Aggregator's job to allocate this
                            BigInteger[] encrypted_response = new BigInteger[queryAndNoise.length - 1];
                            for (int i = 1; i < queryAndNoise.length; i++) {
                                String[] dict = queryAndNoise[i].split(":");
                                double noise = laplace(Double.parseDouble(dict[1]));
                                int aggregate = results.getInt(dict[0]);
                                BigInteger aggregatePlusNoise = BigInteger.valueOf(Math.round(aggregate + noise) * 100);
                                BigInteger encrypted_message = encryptionKey.encrypt(aggregatePlusNoise);
                                encrypted_response[i - 1] = encrypted_message;

                                //]Remember we're sending back 100 times the values we're looking for.
                                // For purposes of odds ratios this won't be problematic but it can show up elsewhere.
                            }
                            objectOutputStream.writeObject(encrypted_response);




                    case 'e': //encrypted text
                        //perform a partial decryption and return
                        objectOutputStream.writeObject(decryptionKey.decryptProof(new BigInteger(serverMessage)));
                    case 'k':
                        socket.close();
                        return;
                }
                objectOutputStream.close();
                objectInputStream.close();
                socket.close();
                serverSocket.close();
            }
        } catch (ClassNotFoundException ex) {
            ex.printStackTrace();
        } catch (SQLException ex) {
            ex.printStackTrace();
        }
    }
}


