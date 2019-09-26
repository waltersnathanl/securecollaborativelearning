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
    public static Object send(InetAddress target, int port, Object message) throws IOException, ClassNotFoundException {
        Socket socket = new Socket(target, 8080);
        OutputStream outputStream = socket.getOutputStream();
        InputStream inputStream = socket.getInputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
        ObjectInputStream objectInputStream = new ObjectInputStream(inputStream);
        objectOutputStream.writeObject(message);
        Object payload = objectInputStream.readObject();
        socket.close();
        return payload;
    }

    public static Object get(int port, Object returnMessage) throws IOException, ClassNotFoundException {
        ServerSocket serverSocket = new ServerSocket(8080);
        Socket socket = serverSocket.accept();
        OutputStream outputStream = socket.getOutputStream();
        InputStream inputStream = socket.getInputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(outputStream);
        ObjectInputStream objectInputStream = new ObjectInputStream((inputStream));
        objectOutputStream.writeObject(returnMessage);
        Object payload = objectInputStream.readObject();
        socket.close();
        return payload;
    }


    public static double laplace(double scale) {
        double exponential_sample1 = -scale * Math.log(Math.random());
        double exponential_sample2 = -scale * Math.log(Math.random());
        return exponential_sample1 - exponential_sample2;
    }

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, SQLException, ClassNotFoundException, NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        //first we talk to the KeyMaster, sending it our public key and getting a paillier key
        int port = 8080;

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024,new SecureRandom());
        KeyPair pair = generator.generateKeyPair();
        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();
        Cipher decryptionCipher = Cipher.getInstance("RSA");
        decryptionCipher.init(Cipher.DECRYPT_MODE,privateKey);

        Object junk;
        InetAddress aggregatorAddress = (InetAddress) get(port,"aggregator address received");
        junk = get(port,publicKey);

        byte[] encryptedPaillierKey = (byte[]) get(port,"confirmed");
        byte[] decryptedPaillierKey = decryptionCipher.doFinal(encryptedPaillierKey);

        PaillierPrivateThresholdKey myKey = new PaillierPrivateThresholdKey(decryptedPaillierKey,1L);
        //the seed is unimportant at this stage, but the constructor wants it.
        PaillierThreshold decryptionKey = new PaillierThreshold(myKey);
        Paillier encryptionKey = new Paillier(decryptionKey.getPublicKey());


        // Now we are talking to the aggregator, which can have longer conversations.
        String serverMessageAndType;
        while (true) {
            serverMessageAndType = (String) get(port,"received");
            char messageType = serverMessageAndType.charAt(0);
            String serverMessage = serverMessageAndType.substring(1);
            System.out.println(messageType);
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
                        System.out.println(dict[0]);
                        int aggregate = results.getInt(dict[0]);
                        BigInteger aggregatePlusNoise = BigInteger.valueOf(Math.round(aggregate + noise) * 100);
                        BigInteger encrypted_message = encryptionKey.encrypt(aggregatePlusNoise);
                        encrypted_response[i - 1] = encrypted_message;
                        //]Remember we're sending back 100 times the values we're looking for.
                        // For purposes of odds ratios this won't be problematic but it can show up elsewhere.
                    }
                    junk = send(aggregatorAddress,port,encrypted_response);
                    break;
                }





                case 'e': {//encrypted text
                        //perform a partial decryption and return
                    junk = send(aggregatorAddress,port,decryptionKey.decrypt((new BigInteger(serverMessage))));
                    break;
                }
                case 'k': {
                    return;
                }
            }
        }
    }
}

